const Tesseract = require('tesseract.js');
const { PNG } = require('pngjs');
const jpeg = require('jpeg-js');
const { calculateScore } = require('../../shared/scoring');
const { maskPreview } = require('../../shared/masking');
const { PaymentScreenshotScanService } = require('../models/PaymentScreenshotScan');

const ALLOWED_MIMES = ['image/jpeg', 'image/jpg', 'image/png'];

/**
 * Validate image buffer magic bytes and extract dimensions + header software traces
 */
function inspectImageBuffer(buffer, mimeType = '') {
  if (!buffer || !Buffer.isBuffer(buffer) || buffer.length < 16) {
    const err = new Error('Invalid or empty image file.');
    err.status = 400;
    throw err;
  }

  const isPng =
    buffer[0] === 0x89 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x4e &&
    buffer[3] === 0x47;

  const isJpeg =
    buffer[0] === 0xff &&
    buffer[1] === 0xd8 &&
    buffer[2] === 0xff;

  if (!isPng && !isJpeg) {
    const err = new Error('Unsupported file format. Only valid PNG, JPG, and JPEG images are accepted.');
    err.status = 400;
    throw err;
  }

  if (mimeType && !ALLOWED_MIMES.includes(mimeType.toLowerCase())) {
    const err = new Error('Unsupported MIME type. Only image/jpeg and image/png are accepted.');
    err.status = 400;
    throw err;
  }

  let width = 0;
  let height = 0;

  try {
    if (isPng) {
      // PNG IHDR chunk has width at bytes 16..19 and height at 20..23
      width = buffer.readUInt32BE(16);
      height = buffer.readUInt32BE(20);
    } else if (isJpeg) {
      const decoded = jpeg.decode(buffer, { useTArray: true, maxMemoryUsageInMB: 128 });
      width = decoded.width;
      height = decoded.height;
    }
  } catch (e) {
    const err = new Error('Corrupted image file. Unable to decode image dimensions.');
    err.status = 400;
    throw err;
  }

  // Scan first 16 KB of file header for image editing software signatures
  const headerSlice = buffer.subarray(0, Math.min(buffer.length, 16384)).toString('latin1');
  const editorMatch = headerSlice.match(/(Adobe Photoshop|Canva|PicsArt|GIMP|Pixellab|Snapseed|Paint\.NET|Illustrator|Figma|Spoof|Fake)/i);

  return {
    format: isPng ? 'PNG' : 'JPEG',
    width,
    height,
    sizeBytes: buffer.length,
    editorSoftwareTrace: editorMatch ? editorMatch[1] : null
  };
}

/**
 * Run OCR on image buffer using Tesseract.js
 */
async function extractTextViaOcr(buffer) {
  try {
    const result = await Tesseract.recognize(buffer, 'eng');
    const rawText = (result && result.data && result.data.text) ? result.data.text : '';
    const confidence = (result && result.data && typeof result.data.confidence === 'number')
      ? Math.round(result.data.confidence)
      : null;
    return { text: rawText.trim(), confidence };
  } catch (err) {
    console.warn('[OCR] Tesseract recognition warning:', err.message);
    return { text: '', confidence: 0 };
  }
}

/**
 * Parse structured transaction fields from OCR text
 */
function parseTransactionFields(ocrText) {
  const clean = (ocrText || '').replace(/\r/g, '\n');
  const lines = clean.split('\n').map(l => l.trim()).filter(Boolean);
  const fullText = lines.join(' ');

  // 1. Detect UPI / Payment App
  let appDetected = 'Unknown / Unidentified App';
  if (/phonepe/i.test(fullText)) appDetected = 'PhonePe';
  else if (/google\s*pay|gpay/i.test(fullText)) appDetected = 'Google Pay (GPay)';
  else if (/paytm/i.test(fullText)) appDetected = 'Paytm';
  else if (/bhim/i.test(fullText)) appDetected = 'BHIM UPI';
  else if (/amazon\s*pay/i.test(fullText)) appDetected = 'Amazon Pay';
  else if (/cred\b/i.test(fullText)) appDetected = 'CRED';
  else if (/\bupi\b/i.test(fullText)) appDetected = 'Generic UPI Receipt';

  // 2. Extract 12-digit UTR / UPI Transaction ID or Ref No
  let transactionId = null;
  const labeledUtrMatch = fullText.match(/(?:UTR|UPI\s*Ref(?:\s*No\.?|\s*ID)?|Transaction\s*ID|Txn\s*ID|Ref(?:erence)?\s*(?:No|ID)?)[:\s#-]*([0-9]{10,16}|[A-Z0-9]{10,22})/i);
  if (labeledUtrMatch) {
    transactionId = labeledUtrMatch[1].trim();
  } else {
    const twelveDigitMatch = fullText.match(/\b(\d{12})\b/);
    if (twelveDigitMatch) {
      transactionId = twelveDigitMatch[1];
    }
  }

  // 3. Extract Payment Amount
  let amount = null;
  const amountLabeledMatch = fullText.match(/(?:₹|Rs\.?|INR)\s*([0-9]{1,3}(?:,[0-9]{2,3})*(?:\.[0-9]{1,2})?|[0-9]+(?:\.[0-9]{1,2})?)/i);
  if (amountLabeledMatch) {
    amount = '₹' + amountLabeledMatch[1];
  } else {
    const paidAmountMatch = fullText.match(/(?:Amount|Paid|Sent|Total)[:\s]*([0-9,]+(?:\.[0-9]{2})?)/i);
    if (paidAmountMatch) {
      amount = '₹' + paidAmountMatch[1];
    }
  }

  // 4. Extract Date & Time
  let dateTime = null;
  const dateRegex = /\b(\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{2,4}(?:[,\s]+\d{1,2}:\d{2}\s*(?:AM|PM)?)?|\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}(?:\s+\d{1,2}:\d{2}\s*(?:AM|PM)?)?)/i;
  const dateMatch = fullText.match(dateRegex);
  const timeMatch = fullText.match(/\b(\d{1,2}:\d{2}\s*(?:AM|PM))\b/i);
  if (dateMatch) {
    dateTime = dateMatch[1];
    if (timeMatch && !dateTime.toLowerCase().includes(timeMatch[1].toLowerCase())) {
      dateTime += ', ' + timeMatch[1];
    }
  } else if (timeMatch) {
    dateTime = timeMatch[1];
  }

  // 5. Extract Sender / Receiver or VPA
  let senderReceiver = null;
  const partyLine = lines.find(l => /^(Paid\s+to|To|Sent\s+to|Received\s+from|From|Banking\s+Name)[:\s]+(.+)/i.test(l));
  const vpaMatch = fullText.match(/[a-zA-Z0-9._-]+@[a-zA-Z]{2,}/);
  if (partyLine) {
    senderReceiver = partyLine.slice(0, 80);
    if (vpaMatch && !senderReceiver.includes(vpaMatch[0])) {
      senderReceiver += ` (${vpaMatch[0]})`;
    }
  } else if (vpaMatch) {
    senderReceiver = vpaMatch[0];
  }

  // 6. Extract Payment Status
  let paymentStatus = null;
  if (/\b(payment\s+successful|transaction\s+successful|paid\s+successfully|completed|money\s+sent|payment\s+complete)\b/i.test(fullText)) {
    paymentStatus = 'Successful / Completed';
  } else if (/\b(pending|processing|in\s+progress|awaiting|initiated)\b/i.test(fullText)) {
    paymentStatus = 'Pending / Processing (Not Settled)';
  } else if (/\b(failed|declined|cancelled|rejected|expired)\b/i.test(fullText)) {
    paymentStatus = 'Failed / Declined';
  } else if (/\b(request\s+money|collect\s+request|pay\s+now)\b/i.test(fullText)) {
    paymentStatus = 'Payment Request (Not Paid)';
  } else if (/\b(paid|success|sent)\b/i.test(fullText)) {
    paymentStatus = 'Paid / Success (Keyword Detected)';
  }

  return {
    transactionId,
    amount,
    dateTime,
    senderReceiver,
    paymentStatus,
    appDetected
  };
}

/**
 * Analyze an uploaded payment screenshot buffer + OCR text
 */
async function analyzePaymentScreenshot(buffer, mimeType = '', clientOcrHint = '') {
  const imageMeta = inspectImageBuffer(buffer, mimeType);
  const ocrResult = await extractTextViaOcr(buffer);

  const combinedText = [ocrResult.text, clientOcrHint || ''].filter(Boolean).join('\n').trim();
  const extracted = parseTransactionFields(combinedText);
  const firedRules = [];

  // Rule 1: Image header contains editing software metadata
  if (imageMeta.editorSoftwareTrace) {
    firedRules.push({
      id: 'PAYMENT_EDITING_SOFTWARE_TRACE',
      title: `Image Editing Software Signature (${imageMeta.editorSoftwareTrace})`,
      weight: 45,
      explanation: `The image file metadata contains traces of "${imageMeta.editorSoftwareTrace}", indicating the screenshot was modified or created in an image editor.`
    });
  }

  // Rule 2: Spoof / Fake receipt generator watermark in OCR text
  if (/(spoof|fakepay|prank|sample\s+receipt|demo\s+payment|photoshop|canva|edit\s+text)/i.test(combinedText)) {
    firedRules.push({
      id: 'PAYMENT_SPOOF_WATERMARK',
      title: 'Fake / Spoof Receipt Generator Text Detected',
      weight: 60,
      explanation: 'The screenshot contains text associated with fake payment receipt generators or editing templates.'
    });
  }

  // Rule 3: Little or no readable transaction text found by OCR
  if (combinedText.length < 15) {
    firedRules.push({
      id: 'PAYMENT_UNREADABLE_OR_BLANK_TEXT',
      title: 'Missing or Unreadable Transaction Text',
      weight: 35,
      explanation: 'OCR could not extract standard payment receipt text from this image. It may be heavily blurred, cropped, or not a payment receipt.'
    });
  }

  // Rule 4: Missing 12-digit UTR / Transaction Reference ID
  if (!extracted.transactionId) {
    firedRules.push({
      id: 'PAYMENT_MISSING_UTR',
      title: 'Missing UPI Transaction ID / 12-Digit UTR',
      weight: 30,
      explanation: 'No 12-digit UPI Reference Number (UTR) or Transaction ID was found. Cropping out or omitting the UTR is a common sign of a manipulated screenshot.'
    });
  } else {
    // Check if UTR looks fabricated (e.g. repeating digits 111111111111, 123456789012, 000000000000)
    const utr = extracted.transactionId;
    if (/^(\d)\1{7,}$/.test(utr) || /12345678|87654321|0000000/.test(utr)) {
      firedRules.push({
        id: 'PAYMENT_FABRICATED_UTR_PATTERN',
        title: 'Suspicious / Sequential Transaction ID Pattern',
        weight: 45,
        explanation: `The extracted transaction reference (${utr}) follows a sequential or repeating placeholder pattern typical of forged screenshots.`
      });
    } else if (/^\d+$/.test(utr) && utr.length !== 12) {
      firedRules.push({
        id: 'PAYMENT_NON_STANDARD_UTR_LENGTH',
        title: `Non-Standard Numeric Reference Length (${utr.length} digits)`,
        weight: 25,
        explanation: 'Standard NPCI UPI UTR numbers are exactly 12 digits long. This reference length is unusual.'
      });
    }

    // Rule 5: Check MongoDB for duplicate UTR across previous scans
    const existingUtrScan = await PaymentScreenshotScanService.findByUtr(utr);
    if (existingUtrScan) {
      firedRules.push({
        id: 'PAYMENT_DUPLICATE_UTR_DETECTED',
        title: 'Duplicate Transaction Reference (UTR Previously Scanned)',
        weight: 35,
        explanation: `Transaction ID "${utr}" was already submitted in an earlier scan. Scammers frequently reuse old or recycled UTR numbers on edited screenshots.`
      });
    }
  }

  // Rule 6: Missing Payment Amount
  if (!extracted.amount) {
    firedRules.push({
      id: 'PAYMENT_MISSING_AMOUNT',
      title: 'Payment Amount Not Clearly Visible',
      weight: 25,
      explanation: 'A clear currency symbol (₹ / Rs / INR) and transaction amount could not be verified in the screenshot.'
    });
  }

  // Rule 7: Missing Date / Timestamp
  if (!extracted.dateTime) {
    firedRules.push({
      id: 'PAYMENT_MISSING_TIMESTAMP',
      title: 'Missing Transaction Date or Time',
      weight: 20,
      explanation: 'No standard transaction date or timestamp was detected on the receipt.'
    });
  }

  // Rule 8: Pending / Failed / Request Status
  if (!extracted.paymentStatus) {
    firedRules.push({
      id: 'PAYMENT_UNCLEAR_STATUS',
      title: 'Unclear or Missing Payment Completion Status',
      weight: 25,
      explanation: 'The screenshot does not clearly display a verified completion status (e.g., Paid / Successful).'
    });
  } else if (extracted.paymentStatus.includes('Pending') || extracted.paymentStatus.includes('Failed') || extracted.paymentStatus.includes('Request')) {
    firedRules.push({
      id: 'PAYMENT_NON_SUCCESS_STATUS',
      title: `Non-Final Payment Status (${extracted.paymentStatus})`,
      weight: 45,
      explanation: `The screenshot shows "${extracted.paymentStatus}". Scammers often share "Processing", "Pending", or "Collect Request" screens while claiming the money has already been sent.`
    });
  }

  // Rule 9: Contradictory status words or unusual aspect ratio
  if (/\b(paid|successful)\b/i.test(combinedText) && /\b(failed|declined|unpaid|insufficient)\b/i.test(combinedText)) {
    firedRules.push({
      id: 'PAYMENT_CONTRADICTORY_STATUS_TEXT',
      title: 'Contradictory Payment Status Keywords',
      weight: 35,
      explanation: 'Both success ("Paid/Successful") and failure ("Failed/Declined") keywords appear in the same screenshot, suggesting text overlay manipulation.'
    });
  }

  if (imageMeta.width > 0 && imageMeta.height > 0 && imageMeta.width > imageMeta.height * 1.3) {
    firedRules.push({
      id: 'PAYMENT_UNUSUAL_ASPECT_RATIO',
      title: `Cropped or Landscape Screenshot Aspect Ratio (${imageMeta.width}x${imageMeta.height})`,
      weight: 15,
      explanation: 'Genuine mobile UPI payment receipts are vertical (portrait). Heavily cropped or wide images may hide key transaction details.'
    });
  }

  const scored = calculateScore(firedRules);
  scored.actions = [
    'ALWAYS open your own official bank app or UPI app (PhonePe, GPay, Paytm, BHIM) and check your transaction history—never rely on a screenshot alone as proof of payment.',
    'Wait for an official bank SMS credit confirmation and verify that your actual account balance has increased before handing over goods or services.',
    'Note: OCR and image analysis highlight suspicious indicators but cannot conclusively detect every forged screenshot.'
  ].concat(scored.actions || []).slice(0, 5);

  const previewRaw = `Payment: ${extracted.amount || 'Unknown Amt'} | UTR: ${extracted.transactionId || 'Missing'}`;

  return {
    type: 'payment',
    score: scored.score,
    riskLevel: scored.riskLevel,
    riskCategory: scored.riskCategory,
    firedRules: scored.firedRules,
    actions: scored.actions,
    disclaimer: 'IMPORTANT: A screenshot NEVER proves that a payment was successful, and OCR/image analysis cannot conclusively detect all forged screenshots. Always verify the actual credit in your official bank or UPI app.',
    extractedInfo: {
      transactionId: extracted.transactionId || 'Not detected',
      amount: extracted.amount || 'Not detected',
      dateTime: extracted.dateTime || 'Not detected',
      senderReceiver: extracted.senderReceiver || 'Not detected',
      paymentStatus: extracted.paymentStatus || 'Unclear / Not detected',
      appDetected: extracted.appDetected
    },
    utrNumber: extracted.transactionId || null,
    imageMeta: {
      format: imageMeta.format,
      width: imageMeta.width,
      height: imageMeta.height,
      sizeBytes: imageMeta.sizeBytes,
      ocrConfidence: ocrResult.confidence
    },
    maskedPreview: maskPreview(previewRaw),
    analyzedAt: scored.analyzedAt
  };
}

module.exports = {
  inspectImageBuffer,
  extractTextViaOcr,
  parseTransactionFields,
  analyzePaymentScreenshot
};

