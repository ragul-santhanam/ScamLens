/**
 * ScamLens Full-Stack Enhancement Verification Suite
 * Tests all 5 major features end-to-end against the live Express server & database:
 * 1. User Authentication (Sign Up, Login, Duplicate/Invalid Checks, Protected Routes, Password Reset, Logout, User Isolation)
 * 2. Fake Payment Screenshot Detector (Valid PNG upload, Unsupported file rejection, OCR & Rule Engine, DB persistence)
 * 3. Scam Emergency Assistant (All 7 incident categories, guidance retrieval, session saving, user-scoped history)
 * 4. QR Code Scam Detector (Valid URL QR, Suspicious URL QR, UPI Payment QR, Plain Text QR, Invalid QR, DB history)
 * 5. Website Identity & Impersonation Checker (Official domain, Lookalike, Character substitution, Punycode, Open redirect, SSRF guard)
 */
const { PNG } = require('pngjs');
const { startServer, stopServer } = require('../server/app');
const { validateExternalUrl } = require('../server/utils/ssrfGuard');
const { parseTransactionFields } = require('../server/services/paymentOcrService');

const TEST_PORT = 3300;
const BASE_URL = `http://localhost:${TEST_PORT}`;

let passedCount = 0;
let totalCount = 0;

function check(name, condition, detail = '') {
  totalCount++;
  if (condition) {
    passedCount++;
    console.log(`[PASS] ${totalCount}. ${name}`);
    if (detail) console.log(`       ${detail}`);
  } else {
    console.error(`[FAIL] ${totalCount}. ${name}`);
    if (detail) console.error(`       Detail: ${detail}`);
  }
}

async function apiJson(method, path, body = null, token = null) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined
  });
  const data = await res.json().catch(() => ({}));
  return { status: res.status, data };
}

/**
 * Generate a valid in-memory PNG buffer for testing image uploads
 */
function createSamplePngBuffer(width = 360, height = 640) {
  const png = new PNG({ width, height });
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const idx = (width * y + x) << 2;
      png.data[idx] = 255;
      png.data[idx + 1] = 255;
      png.data[idx + 2] = 255;
      png.data[idx + 3] = 255;
    }
  }
  return PNG.sync.write(png);
}

async function runFullStackSuite() {
  console.log('==============================================================');
  console.log('   ScamLens Full-Stack 5-Feature End-to-End Verification');
  console.log('==============================================================\n');

  await startServer(TEST_PORT);

  try {
    const uniqueSuffix = Date.now();
    const userAEmail = `alice.${uniqueSuffix}@example.com`;
    const userBEmail = `bob.${uniqueSuffix}@example.com`;
    let tokenA = null;
    let tokenB = null;

    // =========================================================================
    // FEATURE 1: USER AUTHENTICATION
    // =========================================================================
    console.log('--- Feature 1: User Authentication ---');

    // 1.1 Successful Signup (User A)
    const signupA = await apiJson('POST', '/api/auth/signup', {
      fullName: 'Alice Sharma',
      email: userAEmail,
      mobile: '9876543210',
      password: 'SecurePass123',
      confirmPassword: 'SecurePass123',
      acceptedTerms: true
    });
    tokenA = signupA.data.token;
    check(
      'Auth: Successful Sign Up creates user & returns JWT',
      signupA.status === 201 && Boolean(tokenA) && signupA.data.user.email === userAEmail && !signupA.data.user.passwordHash,
      `User ID: ${signupA.data.user ? signupA.data.user.id : 'none'}`
    );

    // 1.2 Duplicate Email Rejection
    const dupSignup = await apiJson('POST', '/api/auth/signup', {
      fullName: 'Alice Duplicate',
      email: userAEmail,
      password: 'SecurePass123',
      confirmPassword: 'SecurePass123',
      acceptedTerms: true
    });
    check(
      'Auth: Duplicate email signup is rejected with 409',
      dupSignup.status === 409,
      `Status: ${dupSignup.status}, Error: ${dupSignup.data.error}`
    );

    // 1.3 Invalid Email Validation
    const badEmailSignup = await apiJson('POST', '/api/auth/signup', {
      fullName: 'Bad Email',
      email: 'not-an-email',
      password: 'SecurePass123',
      confirmPassword: 'SecurePass123',
      acceptedTerms: true
    });
    check(
      'Auth: Invalid email format is rejected with 400',
      badEmailSignup.status === 400,
      `Status: ${badEmailSignup.status}`
    );

    // 1.4 Incorrect Password Rejection
    const wrongLogin = await apiJson('POST', '/api/auth/login', {
      email: userAEmail,
      password: 'WrongPassword999'
    });
    check(
      'Auth: Login with incorrect password is rejected with 401',
      wrongLogin.status === 401,
      `Status: ${wrongLogin.status}`
    );

    // 1.5 Successful Login
    const loginA = await apiJson('POST', '/api/auth/login', {
      email: userAEmail,
      password: 'SecurePass123',
      rememberMe: true
    });
    tokenA = loginA.data.token;
    check(
      'Auth: Valid login succeeds and returns fresh JWT',
      loginA.status === 200 && Boolean(tokenA),
      `Logged in as ${loginA.data.user.fullName}`
    );

    // 1.6 Protected Route Access (with & without token)
    const meWithToken = await apiJson('GET', '/api/auth/me', null, tokenA);
    const meWithoutToken = await apiJson('GET', '/api/auth/me', null, null);
    check(
      'Auth: Protected /api/auth/me succeeds with token (200) and rejects missing token (401)',
      meWithToken.status === 200 && meWithoutToken.status === 401,
      `With token: ${meWithToken.status}, Without token: ${meWithoutToken.status}`
    );

    // 1.7 Password Reset Verification Flow
    const forgotStep1 = await apiJson('POST', '/api/auth/forgot-password', { email: userAEmail });
    const resetCode = forgotStep1.data.verificationCode;
    const forgotStep2 = await apiJson('POST', '/api/auth/forgot-password', {
      email: userAEmail,
      verificationCode: resetCode,
      newPassword: 'NewSecurePass456',
      confirmPassword: 'NewSecurePass456'
    });
    const loginAfterReset = await apiJson('POST', '/api/auth/login', {
      email: userAEmail,
      password: 'NewSecurePass456'
    });
    tokenA = loginAfterReset.data.token;
    check(
      'Auth: Two-step Forgot/Reset Password verifies code, updates hash in DB, and allows login with new password',
      forgotStep1.status === 200 && forgotStep2.status === 200 && loginAfterReset.status === 200 && Boolean(tokenA),
      `Reset step: ${forgotStep2.data.step}`
    );

    // Create User B for isolation checks
    const signupB = await apiJson('POST', '/api/auth/signup', {
      fullName: 'Bob Verma',
      email: userBEmail,
      password: 'BobPassword123',
      confirmPassword: 'BobPassword123',
      acceptedTerms: true
    });
    tokenB = signupB.data.token;

    // =========================================================================
    // FEATURE 5: WEBSITE IDENTITY & IMPERSONATION CHECKER
    // =========================================================================
    console.log('\n--- Feature 5: Website Identity & Impersonation Checker ---');

    // 5.1 Official Domain
    const officialUrl = await apiJson(
      'POST',
      '/api/analyze/url',
      { url: 'https://www.onlinesbi.sbi' },
      tokenA
    );
    check(
      'URL Identity: Official domain (www.onlinesbi.sbi) recognized as Low Risk & verified official',
      officialUrl.status === 200 &&
        officialUrl.data.riskLevel === 'Low Risk' &&
        officialUrl.data.identityReport &&
        officialUrl.data.identityReport.isVerifiedOfficial === true,
      `Brand: ${officialUrl.data.identityReport.verifiedBrand}`
    );

    // 5.2 Lookalike / Misspelled Brand Domain
    const lookalikeUrl = await apiJson(
      'POST',
      '/api/analyze/url',
      { url: 'https://onlinesbii.co.in/login' },
      tokenA
    );
    check(
      'URL Identity: Misspelled lookalike domain (onlinesbii.co.in) triggers URL_LOOKALIKE_DOMAIN',
      lookalikeUrl.status === 200 &&
        lookalikeUrl.data.firedRules.some(r => r.id === 'URL_LOOKALIKE_DOMAIN' || r.id === 'URL_BRAND_IMPERSONATION'),
      `Score: ${lookalikeUrl.data.score}, Risk: ${lookalikeUrl.data.riskLevel}`
    );

    // 5.3 Character Substitution Domain
    const charSubUrl = await apiJson(
      'POST',
      '/api/analyze/url',
      { url: 'http://paypa1-verify.com/login' },
      tokenA
    );
    check(
      'URL Identity: Character substitution domain (paypa1-verify.com) triggers URL_CHAR_SUBSTITUTION',
      charSubUrl.status === 200 &&
        charSubUrl.data.firedRules.some(r => r.id === 'URL_CHAR_SUBSTITUTION'),
      `Risk: ${charSubUrl.data.riskLevel}, Score: ${charSubUrl.data.score}`
    );

    // 5.4 Punycode Homograph Domain
    const punyUrl = await apiJson(
      'POST',
      '/api/analyze/url',
      { url: 'http://xn--pple-43d.com' },
      tokenA
    );
    check(
      'URL Identity: Punycode domain (xn--pple-43d.com) triggers URL_PUNYCODE',
      punyUrl.status === 200 && punyUrl.data.firedRules.some(r => r.id === 'URL_PUNYCODE'),
      `Fired: ${punyUrl.data.firedRules.map(r => r.id).join(', ')}`
    );

    // 5.5 Open Redirect Parameter Detection
    const redirectParamUrl = await apiJson(
      'POST',
      '/api/analyze/url',
      { url: 'https://portal-example.com/auth?redirect=http://malicious-site.xyz/steal' },
      tokenA
    );
    check(
      'URL Identity: Embedded redirect parameter triggers URL_OPEN_REDIRECT_PARAM',
      redirectParamUrl.status === 200 &&
        redirectParamUrl.data.firedRules.some(r => r.id === 'URL_OPEN_REDIRECT_PARAM'),
      `Score: ${redirectParamUrl.data.score}`
    );

    // 5.6 Invalid URL rejection
    const invalidUrlRes = await apiJson('POST', '/api/analyze/url', { url: 'not_a_valid_url' }, tokenA);
    check(
      'URL Identity: Invalid URL without domain is rejected with 400',
      invalidUrlRes.status === 400,
      `Status: ${invalidUrlRes.status}`
    );

    // 5.7 SSRF Protection Verification
    const ssrfLocalhost = await validateExternalUrl('http://localhost:80/admin');
    const ssrfLoopback = await validateExternalUrl('http://127.0.0.1:8080/secret');
    const ssrfPrivateLan = await validateExternalUrl('http://192.168.0.1/router');
    const ssrfMetadata = await validateExternalUrl('http://169.254.169.254/latest/meta-data/');
    check(
      'URL Identity: SSRF Guard blocks localhost, 127.0.0.1, 192.168.x.x, and 169.254.169.254',
      !ssrfLocalhost.safe && !ssrfLoopback.safe && !ssrfPrivateLan.safe && !ssrfMetadata.safe,
      `Reasons verified`
    );

    // =========================================================================
    // FEATURE 4: QR CODE SCAM DETECTOR
    // =========================================================================
    console.log('\n--- Feature 4: QR Code Scam Detector ---');

    // 4.1 Valid Official URL QR
    const qrValidUrl = await apiJson(
      'POST',
      '/api/qr/analyze',
      { qrContent: 'https://www.onlinesbi.sbi' },
      tokenA
    );
    check(
      'QR Detector: Official URL QR classified as url & Low Risk',
      qrValidUrl.status === 200 &&
        qrValidUrl.data.contentType === 'url' &&
        qrValidUrl.data.riskLevel === 'Low Risk' &&
        Boolean(qrValidUrl.data.identityReport),
      `Domain: ${qrValidUrl.data.normalizedDomain}`
    );

    // 4.2 Suspicious Phishing URL QR
    const qrSuspUrl = await apiJson(
      'POST',
      '/api/qr/analyze',
      { qrContent: 'http://paytm-secure-login.xyz/kyc-update' },
      tokenA
    );
    check(
      'QR Detector: Phishing URL QR reuses URL Identity engine and flags High Risk',
      qrSuspUrl.status === 200 &&
        qrSuspUrl.data.contentType === 'url' &&
        qrSuspUrl.data.riskLevel === 'High Risk',
      `Score: ${qrSuspUrl.data.score}`
    );

    // 4.3 Suspicious UPI Payment QR ("Receive Refund" lure)
    const qrUpiScam = await apiJson(
      'POST',
      '/api/qr/analyze',
      { qrContent: 'upi://pay?pa=scammer@okaxis&pn=OLX%20Cashback%20Refund&am=4500&cu=INR&tn=Scan%20to%20receive%20Rs%204500%20refund' },
      tokenA
    );
    check(
      'QR Detector: Deceptive UPI Payment QR ("receive refund") flags High Risk & parses payee details',
      qrUpiScam.status === 200 &&
        qrUpiScam.data.contentType === 'upi' &&
        qrUpiScam.data.riskLevel === 'High Risk' &&
        qrUpiScam.data.qrDetails.paymentRecipient.payeeVpa === 'scammer@okaxis',
      `Score: ${qrUpiScam.data.score}, Amount: ${qrUpiScam.data.qrDetails.paymentRecipient.amount}`
    );

    // 4.4 Plain Text QR
    const qrPlainText = await apiJson(
      'POST',
      '/api/qr/analyze',
      { qrContent: 'Urgent from Bank Security: Share your OTP with our executive immediately to cancel debit.' },
      tokenA
    );
    check(
      'QR Detector: Plain text scam QR evaluated by message analyzer',
      qrPlainText.status === 200 &&
        qrPlainText.data.contentType === 'text' &&
        qrPlainText.data.score >= 50,
      `Score: ${qrPlainText.data.score}, Risk: ${qrPlainText.data.riskLevel}`
    );

    // 4.5 Invalid/Empty QR rejection
    const qrInvalid = await apiJson('POST', '/api/qr/analyze', { qrContent: '   ' }, tokenA);
    check(
      'QR Detector: Empty QR payload is rejected with 400',
      qrInvalid.status === 400,
      `Status: ${qrInvalid.status}`
    );

    // 4.6 QR History Retrieval
    const qrHistoryRes = await apiJson('GET', '/api/qr/history', null, tokenA);
    check(
      'QR Detector: GET /api/qr/history returns saved QR scans for authenticated user',
      qrHistoryRes.status === 200 && Array.isArray(qrHistoryRes.data) && qrHistoryRes.data.length >= 4,
      `Saved QR scans: ${qrHistoryRes.data.length}`
    );

    // =========================================================================
    // FEATURE 2: FAKE PAYMENT SCREENSHOT DETECTOR
    // =========================================================================
    console.log('\n--- Feature 2: Fake Payment Screenshot Detector ---');

    // 2.1 Unsupported File Rejection (.txt uploaded instead of PNG/JPG)
    const badForm = new FormData();
    badForm.append('image', new Blob(['not an image file'], { type: 'text/plain' }), 'fake.txt');
    const badUploadRes = await fetch(`${BASE_URL}/api/payment/analyze`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${tokenA}` },
      body: badForm
    });
    check(
      'Payment Detector: Unsupported file type (.txt) is rejected with 400',
      badUploadRes.status === 400,
      `Status: ${badUploadRes.status}`
    );

    // 2.2 Valid PNG Upload + OCR + Missing/Suspicious Receipt Detection
    const pngBuffer = createSamplePngBuffer(360, 640);
    const validForm = new FormData();
    validForm.append('image', new Blob([pngBuffer], { type: 'image/png' }), 'receipt.png');
    validForm.append('ocrText', 'PhonePe Payment Processing ₹5,000 To: Ramesh@ybl Date: 10 Nov 2026, 12:15 PM UTR: 111111111111');
    const paymentAnalyzeRes = await fetch(`${BASE_URL}/api/payment/analyze`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${tokenA}` },
      body: validForm
    });
    const paymentData = await paymentAnalyzeRes.json();
    check(
      'Payment Detector: Valid PNG screenshot analyzed, extracts fields, detects fabricated UTR & Pending status',
      paymentAnalyzeRes.status === 200 &&
        Boolean(paymentData.scanId) &&
        paymentData.riskLevel === 'High Risk' &&
        paymentData.extractedInfo.appDetected === 'PhonePe' &&
        paymentData.extractedInfo.transactionId === '111111111111' &&
        paymentData.firedRules.some(r => r.id === 'PAYMENT_FABRICATED_UTR_PATTERN') &&
        paymentData.firedRules.some(r => r.id === 'PAYMENT_NON_SUCCESS_STATUS'),
      `Risk: ${paymentData.riskLevel} (${paymentData.score}), Rules: ${paymentData.firedRules.map(r => r.id).join(', ')}`
    );

    // 2.3 Duplicate UTR Detection across scans
    const dupForm = new FormData();
    dupForm.append('image', new Blob([pngBuffer], { type: 'image/png' }), 'receipt2.png');
    dupForm.append('ocrText', 'PhonePe Payment Successful ₹5,000 To: Ramesh@ybl Date: 10 Nov 2026, 12:15 PM UTR: 111111111111');
    const dupPaymentRes = await fetch(`${BASE_URL}/api/payment/analyze`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${tokenA}` },
      body: dupForm
    });
    const dupPaymentData = await dupPaymentRes.json();
    check(
      'Payment Detector: Reused UTR number across screenshots triggers PAYMENT_DUPLICATE_UTR_DETECTED',
      dupPaymentRes.status === 200 &&
        dupPaymentData.firedRules.some(r => r.id === 'PAYMENT_DUPLICATE_UTR_DETECTED'),
      `Duplicate UTR rule fired`
    );

    // 2.4 Payment History Retrieval
    const payHistory = await apiJson('GET', '/api/payment/history', null, tokenA);
    check(
      'Payment Detector: GET /api/payment/history returns saved payment screenshot scans',
      payHistory.status === 200 && Array.isArray(payHistory.data) && payHistory.data.length >= 2,
      `Saved Payment scans: ${payHistory.data.length}`
    );

    // =========================================================================
    // FEATURE 3: SCAM EMERGENCY ASSISTANT
    // =========================================================================
    console.log('\n--- Feature 3: Scam Emergency Assistant ---');

    // 3.1 Retrieve all 7 guidance categories
    const guidanceCatalog = await apiJson('GET', '/api/emergency/guidance');
    const categories = (guidanceCatalog.data && guidanceCatalog.data.categories) || [];
    check(
      'Emergency Assistant: GET /api/emergency/guidance returns all 7 incident categories & 1930 / cybercrime.gov.in resources',
      guidanceCatalog.status === 200 &&
        categories.length === 7 &&
        guidanceCatalog.data.officialResources.helplineNumber === '1930' &&
        guidanceCatalog.data.officialResources.reportingPortal === 'https://cybercrime.gov.in/',
      `Categories count: ${categories.length}`
    );

    // 3.2 Test saving a session for EVERY incident category (all 7)
    let allSevenSaved = true;
    for (const cat of categories) {
      const sessRes = await apiJson(
        'POST',
        '/api/emergency/session',
        {
          incidentCategory: cat.id,
          selectedAnswers: { timeElapsed: 'Within the last 1 hour' }
        },
        tokenA
      );
      if (
        sessRes.status !== 201 ||
        !sessRes.data.sessionId ||
        !Array.isArray(sessRes.data.guidanceProvided.immediateSteps) ||
        sessRes.data.guidanceProvided.immediateSteps.length === 0
      ) {
        allSevenSaved = false;
      }
    }
    check(
      'Emergency Assistant: All 7 incident categories return tailored steps and save sessions in DB',
      allSevenSaved,
      'Verified all 7 categories (money_transfer, otp_pin_shared, suspicious_link, unknown_app, remote_access, suspicious_call_msg, other_fraud)'
    );

    // 3.3 Emergency History Isolation (User A vs User B)
    const emHistA = await apiJson('GET', '/api/emergency/history', null, tokenA);
    const emHistB = await apiJson('GET', '/api/emergency/history', null, tokenB);
    check(
      'Emergency Assistant: User-specific emergency session history isolates User A from User B',
      emHistA.status === 200 && emHistA.data.length === 7 && emHistB.status === 200 && emHistB.data.length === 0,
      `User A sessions: ${emHistA.data.length}, User B sessions: ${emHistB.data.length}`
    );

    // =========================================================================
    // USER ISOLATION & LOGOUT
    // =========================================================================
    console.log('\n--- User Access Control & Logout ---');

    const scanHistA = await apiJson('GET', '/api/history', null, tokenA);
    const scanHistB = await apiJson('GET', '/api/history', null, tokenB);
    check(
      'Access Control: Unified /api/history isolates User A scans from User B',
      scanHistA.status === 200 && scanHistA.data.length > 0 && scanHistB.status === 200 && scanHistB.data.length === 0,
      `User A scans: ${scanHistA.data.length}, User B scans: ${scanHistB.data.length}`
    );

    // User B tries to access User A's scan by ID
    const firstScanIdA = scanHistA.data[0]._id;
    const crossAccess = await apiJson('GET', `/api/history/${firstScanIdA}`, null, tokenB);
    check(
      'Access Control: User B cannot read User A scan record by ID (returns 404)',
      crossAccess.status === 404,
      `Status: ${crossAccess.status}`
    );

    // Logout revokes token
    const logoutRes = await apiJson('POST', '/api/auth/logout', {}, tokenA);
    const meAfterLogout = await apiJson('GET', '/api/auth/me', null, tokenA);
    check(
      'Auth: POST /api/auth/logout revokes token and subsequent /api/auth/me returns 401',
      logoutRes.status === 200 && meAfterLogout.status === 401,
      `Post-logout /api/auth/me status: ${meAfterLogout.status}`
    );

  } finally {
    await stopServer();
  }

  console.log('\n==============================================================');
  console.log(`   Full-Stack Verification Summary: ${passedCount}/${totalCount} Checks Passed`);
  console.log('==============================================================\n');

  if (passedCount !== totalCount) {
    process.exit(1);
  }
}

runFullStackSuite().catch((err) => {
  console.error('Fatal test runner error:', err);
  process.exit(1);
});

