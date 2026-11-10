const jsQR = require('jsqr');
const { PNG } = require('pngjs');
const jpeg = require('jpeg-js');
const { analyzeUrlWithIdentity } = require('./urlIdentityService');
const { analyzeMessage } = require('../../shared/messageAnalyzer');
const { calculateScore } = require('../../shared/scoring');
const { maskPreview } = require('../../shared/masking');

/**
 * Decode a QR image buffer (PNG or JPEG) into raw QR string using jsQR
 */
function decodeQrFromImageBuffer(buffer, mimeType = '') {
  if (!buffer || !Buffer.isBuffer(buffer)) {
    throw new Error('Invalid image buffer.');
  }

  let width = 0;
  let height = 0;
  let rgbaData = null;

  const isPng =
    mimeType.includes('png') ||
    (buffer.length > 8 && buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47);
  const isJpeg =
    mimeType.includes('jpeg') ||
    mimeType.includes('jpg') ||
    (buffer.length > 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff);

  if (isPng) {
    const png = PNG.sync.read(buffer);
    width = png.width;
    height = png.height;
    rgbaData = new Uint8ClampedArray(png.data);
  } else if (isJpeg) {
    const decoded = jpeg.decode(buffer, { useTArray: true, maxMemoryUsageInMB: 128 });
    width = decoded.width;
    height = decoded.height;
    rgbaData = new Uint8ClampedArray(decoded.data);
  } else {
    const err = new Error('Unsupported image format. Please upload a PNG, JPG, or JPEG image.');
    err.status = 400;
    throw err;
  }

  const code = jsQR(rgbaData, width, height, { inversionAttempts: 'attemptBoth' });
  if (!code || !code.data) {
    const err = new Error('No readable QR code was found in the uploaded image.');
    err.status = 400;
    throw err;
  }

  return code.data;
}

/**
 * Parse and analyze a UPI / Payment URI (e.g. upi://pay?pa=...&pn=...&am=...)
 */
function analyzeUpiQr(rawContent) {
  const firedRules = [];
  let parsedUrl = null;
  try {
    parsedUrl = new URL(rawContent);
  } catch (e) {
    // Fallback query extraction
  }

  const lowerRaw = rawContent.toLowerCase();
  const isMandate = lowerRaw.startsWith('upi://mandate') || lowerRaw.includes('recur=') || lowerRaw.includes('validityend=');

  const params = parsedUrl ? parsedUrl.searchParams : new URLSearchParams(rawContent.split('?')[1] || '');
  const payeeVpa = (params.get('pa') || '').trim();
  const payeeName = (params.get('pn') || '').trim();
  const amountRaw = (params.get('am') || '').trim();
  const currency = (params.get('cu') || 'INR').trim();
  const txnNote = (params.get('tn') || '').trim();
  const txnRef = (params.get('tr') || params.get('tid') || '').trim();
  const merchantCode = (params.get('mc') || '').trim();

  const amountNum = amountRaw ? parseFloat(amountRaw) : null;

  // 1. Check for AutoPay / Recurring Mandate QR
  if (isMandate) {
    firedRules.push({
      id: 'QR_UPI_MANDATE_AUTOPAY',
      title: 'UPI AutoPay / Recurring Debit Mandate QR',
      weight: 45,
      explanation: 'This QR code configures a recurring UPI mandate that can automatically deduct funds from your account.'
    });
  }

  // 2. Check for "Scan to Receive Money / Cashback / Refund" scam lure in note or payee name
  const lureRegex = /(receive|refund|cashback|reward|prize|won|claim|credit|lottery|bonus|kyc|verification|unblock|army|cisf|olx)/i;
  if (lureRegex.test(txnNote) || lureRegex.test(payeeName)) {
    firedRules.push({
      id: 'QR_UPI_RECEIVE_MONEY_SCAM',
      title: 'Deceptive "Receive/Refund/Cashback" Lure in Payment QR',
      weight: 60,
      explanation: 'This payment QR contains terms like "' + (txnNote || payeeName) + '" suggesting you will receive money. Scanning a UPI QR and entering your PIN ALWAYS sends money OUT of your account.'
    });
  }

  // 3. Check for Impersonation of Official/Bank/Govt entity in Payee Name
  const officialImpersonationRegex = /(sbi|hdfc|icici|axis|rbi|npci|cyber|police|income\s*tax|customs|electricity|bescom|paytm\s*kyc|phonepe\s*support|customer\s*care|helpline)/i;
  if (officialImpersonationRegex.test(payeeName) || officialImpersonationRegex.test(payeeVpa)) {
    firedRules.push({
      id: 'QR_UPI_ENTITY_IMPERSONATION',
      title: 'Suspicious Institution/Support Name in UPI Recipient',
      weight: 35,
      explanation: 'The recipient name or UPI ID references a bank, utility, or support desk. Official customer care never collects payments via personal QR codes.'
    });
  }

  // 4. Pre-filled Payment Amount Warning
  if (amountNum !== null && !isNaN(amountNum) && amountNum > 0) {
    if (amountNum >= 5000) {
      firedRules.push({
        id: 'QR_UPI_HIGH_PREFILLED_AMOUNT',
        title: `High Pre-Filled Payment Amount (${currency} ${amountNum})`,
        weight: 30,
        explanation: `This QR code automatically locks in an outgoing payment request of ${currency} ${amountNum}. Verify the amount and recipient carefully.`
      });
    } else {
      firedRules.push({
        id: 'QR_UPI_PREFILLED_AMOUNT',
        title: `Pre-Filled Outgoing Payment Amount (${currency} ${amountNum})`,
        weight: 20,
        explanation: `This QR code pre-fills an outgoing payment of ${currency} ${amountNum}. Remember: entering a UPI PIN deducts money from your account.`
      });
    }
  }

  // 5. Missing or Malformed Payee VPA
  if (!payeeVpa || !payeeVpa.includes('@')) {
    firedRules.push({
      id: 'QR_UPI_INVALID_VPA',
      title: 'Missing or Incomplete UPI ID (VPA)',
      weight: 30,
      explanation: 'The payment URI is missing a standard payee UPI address (username@bankhandle).'
    });
  }

  const scored = calculateScore(firedRules);
  const vpaHandle = payeeVpa.includes('@') ? '@' + payeeVpa.split('@')[1] : '';

  const qrDetails = {
    contentType: 'upi',
    summary: 'UPI Payment Request QR Code',
    paymentRecipient: {
      payeeName: payeeName || 'Not specified in QR',
      payeeVpa: payeeVpa || 'Not specified',
      bankHandle: vpaHandle || 'Unknown',
      amount: amountNum !== null && !isNaN(amountNum) ? `${currency} ${amountNum.toFixed(2)}` : 'User-entered amount',
      transactionNote: txnNote || 'None',
      transactionRef: txnRef || 'None',
      merchantCategory: merchantCode || 'Unclassified / Individual',
      isMandate
    },
    verificationNotice: 'IMPORTANT: ScamLens cannot verify the real-world identity of this recipient. Scanning a payment QR and entering your UPI PIN ALWAYS sends money FROM your account—it is never needed to receive money.'
  };

  scored.actions = [
    'NEVER enter your UPI PIN if someone claimed scanning this QR code will credit or refund money to you.',
    'Confirm the recipient UPI ID (' + (payeeVpa || 'unknown') + ') and name directly with the intended person or merchant before paying.',
    'ScamLens never initiates payments automatically. Only proceed inside your official UPI app if you intend to send money.'
  ].concat(scored.actions || []).slice(0, 5);

  const previewBase = `UPI Pay: ${payeeName || payeeVpa || 'Unknown'} ${amountNum ? 'Rs ' + amountNum : ''}`;

  return {
    type: 'qr',
    contentType: 'upi',
    extractedContent: rawContent,
    extractedUrl: null,
    qrDetails,
    score: scored.score,
    riskLevel: scored.riskLevel,
    riskCategory: scored.riskCategory,
    firedRules: scored.firedRules,
    actions: scored.actions,
    disclaimer: scored.disclaimer,
    maskedPreview: maskPreview(previewBase),
    analyzedAt: scored.analyzedAt
  };
}

/**
 * Analyze extracted QR Code content (URL, UPI payment URI, or plain text)
 */
async function analyzeQrContent(rawQrContent) {
  if (!rawQrContent || typeof rawQrContent !== 'string' || !rawQrContent.trim()) {
    const err = new Error('QR code content is required and must not be empty.');
    err.status = 400;
    throw err;
  }

  const trimmed = rawQrContent.trim();
  if (trimmed.length > 4096) {
    const err = new Error('QR code content exceeds maximum allowed length (4096 chars).');
    err.status = 400;
    throw err;
  }

  // 1. Check if it is a UPI / Payment URI
  if (/^(upi|bhim|paytmmp|phonepe|gpay):\/\//i.test(trimmed)) {
    return analyzeUpiQr(trimmed);
  }

  // 2. Check if the entire QR is a URL or contains an embedded URL
  const isDirectUrl = /^(https?:\/\/|www\.)[^\s]+$/i.test(trimmed) ||
    (/^[a-z0-9-]+(\.[a-z0-9-]+)+(\/[^\s]*)?$/i.test(trimmed) && !trimmed.includes(' '));

  if (isDirectUrl) {
    const urlResult = await analyzeUrlWithIdentity(trimmed);
    const qrDetails = {
      contentType: 'url',
      summary: 'Website Link QR Code',
      destinationUrl: urlResult.enteredUrl,
      normalizedDomain: urlResult.normalizedDomain,
      identityReport: urlResult.identityReport,
      verificationNotice: 'ScamLens never opens QR links automatically. Review the domain identity and risk indicators below before visiting.'
    };

    return {
      type: 'qr',
      contentType: 'url',
      extractedContent: trimmed,
      extractedUrl: urlResult.enteredUrl,
      normalizedDomain: urlResult.normalizedDomain,
      identityReport: urlResult.identityReport,
      qrDetails,
      score: urlResult.score,
      riskLevel: urlResult.riskLevel,
      riskCategory: urlResult.riskCategory,
      firedRules: urlResult.firedRules,
      actions: [
        'Do not open this QR destination if you were asked to scan it for KYC, parcel delivery, or prize claims.',
        ...urlResult.actions
      ].slice(0, 5),
      disclaimer: urlResult.disclaimer,
      maskedPreview: ('QR Link: ' + (urlResult.maskedPreview || urlResult.normalizedDomain)).slice(0, 60),
      analyzedAt: urlResult.analyzedAt
    };
  }

  // 3. Plain text / message / embedded URL inside text QR
  const msgResult = analyzeMessage(trimmed);
  const embeddedUrlMatch = trimmed.match(/https?:\/\/[^\s]+/i);
  let embeddedUrlReport = null;
  if (embeddedUrlMatch) {
    const uRes = await analyzeUrlWithIdentity(embeddedUrlMatch[0]);
    embeddedUrlReport = uRes.identityReport;
  }

  const qrDetails = {
    contentType: 'text',
    summary: 'Text / Data Payload QR Code',
    extractedUrl: embeddedUrlMatch ? embeddedUrlMatch[0] : null,
    identityReport: embeddedUrlReport,
    verificationNotice: 'This QR code contains plain text data. Exercise caution with any phone numbers, links, or instructions inside.'
  };

  return {
    type: 'qr',
    contentType: 'text',
    extractedContent: trimmed,
    extractedUrl: embeddedUrlMatch ? embeddedUrlMatch[0] : null,
    identityReport: embeddedUrlReport,
    qrDetails,
    score: msgResult.score,
    riskLevel: msgResult.riskLevel,
    riskCategory: msgResult.riskCategory,
    firedRules: msgResult.firedRules,
    actions: msgResult.actions,
    disclaimer: msgResult.disclaimer,
    maskedPreview: ('QR Text: ' + msgResult.maskedPreview).slice(0, 60),
    analyzedAt: msgResult.analyzedAt
  };
}

module.exports = {
  decodeQrFromImageBuffer,
  analyzeQrContent,
  analyzeUpiQr
};

