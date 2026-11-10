/**
 * ScamLens End-to-End Test Suite
 * Tests live Express API server against all security, isolation, and masking requirements.
 */
const http = require('http');
const { randomUUID } = require('crypto');
const { startServer, stopServer } = require('../server/app');

const TEST_PORT = 3100;
const BASE_URL = `http://localhost:${TEST_PORT}`;

let server = null;
let checksPassed = 0;
let totalChecks = 0;

function printCheck(num, title, passed, details = '') {
  totalChecks++;
  if (passed) {
    checksPassed++;
    console.log(`[PASS] Check ${num}: ${title}`);
    if (details) console.log(`       ${details}`);
  } else {
    console.error(`[FAIL] Check ${num}: ${title}`);
    if (details) console.error(`       Error: ${details}`);
  }
}

function request(method, path, body = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const options = {
      method: method,
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      headers: {
        'Content-Type': 'application/json'
      }
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        let parsed = null;
        try {
          parsed = JSON.parse(data);
        } catch (e) {
          parsed = data;
        }
        resolve({ status: res.statusCode, headers: res.headers, data: parsed });
      });
    });

    req.on('error', reject);
    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}

async function runE2ETests() {
  console.log('====================================================');
  console.log('       ScamLens End-to-End (E2E) Server Tests');
  console.log('====================================================\n');

  try {
    server = await startServer(TEST_PORT);
  } catch (err) {
    console.error('Failed to start test server:', err);
    process.exit(1);
  }

  const deviceIdA = randomUUID();
  const deviceIdB = randomUUID();
  let createdScanId = null;

  try {
    // Check 1: /api/health
    const healthRes = await request('GET', '/api/health');
    const healthOk = healthRes.status === 200 &&
                     healthRes.data.status === 'ok' &&
                     (healthRes.data.db === 'connected' || healthRes.data.db === 'disconnected');
    printCheck(1, '/api/health returns status ok and db connectivity indicator', healthOk,
      `Status: ${healthRes.data.status}, DB: ${healthRes.data.db}`);

    // Check 2: posting message with phone & OTP creates Scan
    const rawMessage = 'Urgent from Bank Security: Unauthorized debit attempt detected. Share your OTP with our security executive immediately to cancel. Contact support at +91 9876543210 or email help@fake-sbi.com or visit https://fake-bank-login.xyz/verify?token=998877';
    const analyzeRes = await request('POST', '/api/analyze/message', {
      text: rawMessage,
      deviceId: deviceIdA
    });

    const analyzeOk = analyzeRes.status === 200 &&
                      Boolean(analyzeRes.data.scanId) &&
                      analyzeRes.data.riskLevel === 'High Risk' &&
                      Array.isArray(analyzeRes.data.firedRules) &&
                      analyzeRes.data.firedRules.length > 0;

    createdScanId = analyzeRes.data.scanId;
    printCheck(2, 'Posting message with phone number and OTP creates a Scan document', analyzeOk,
      `ScanId: ${createdScanId}, Risk: ${analyzeRes.data.riskLevel}, Score: ${analyzeRes.data.score}`);

    // Check 3: maskedPreview compliance
    const historyRes = await request('GET', `/api/history/${createdScanId}?deviceId=${deviceIdA}`);
    const preview = historyRes.data.maskedPreview || '';

    const hasRunOf4Digits = /\d{4,}/.test(preview);
    const hasRawUrl = /https?:\/\//i.test(preview);
    const hasEmail = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/i.test(preview);
    const hasPhone = /\b[6-9]\d{9}\b/.test(preview);
    const lengthValid = preview.length <= 60 && preview.length > 0;

    const maskingPassed = !hasRunOf4Digits && !hasRawUrl && !hasEmail && !hasPhone && lengthValid;
    printCheck(3, 'Stored maskedPreview has no 4+ digits, no raw URL, no email/phone, <= 60 chars', maskingPassed,
      `Preview: "${preview}" (Length: ${preview.length})`);

    // Check 4: GET /api/history deviceId isolation
    const historyListA = await request('GET', `/api/history?deviceId=${deviceIdA}`);
    const historyListB = await request('GET', `/api/history?deviceId=${deviceIdB}`);

    const isolationPassed = Array.isArray(historyListA.data) &&
                            historyListA.data.some(s => s._id.toString() === createdScanId.toString()) &&
                            Array.isArray(historyListB.data) &&
                            historyListB.data.length === 0;

    printCheck(4, 'GET /api/history strictly isolates scans per deviceId', isolationPassed,
      `Device A Scans: ${historyListA.data.length}, Device B Scans: ${historyListB.data.length}`);

    // Check 5: DELETE /api/history/:id and DELETE /api/history
    const delSingle = await request('DELETE', `/api/history/${createdScanId}?deviceId=${deviceIdA}`);
    const singleDelPassed = delSingle.status === 200 && delSingle.data.success === true;

    // Verify it is gone
    const verifyDel = await request('GET', `/api/history/${createdScanId}?deviceId=${deviceIdA}`);
    const gonePassed = verifyDel.status === 404;

    // Add 2 scans and clear all
    await request('POST', '/api/analyze/url', { url: 'https://paytm.com', deviceId: deviceIdA });
    await request('POST', '/api/analyze/url', { url: 'https://onlinesbi.sbi', deviceId: deviceIdA });

    const delAll = await request('DELETE', `/api/history?deviceId=${deviceIdA}`);
    const clearAllPassed = delAll.status === 200 && delAll.data.deletedCount >= 2;

    const checkEmpty = await request('GET', `/api/history?deviceId=${deviceIdA}`);
    const isEmpty = Array.isArray(checkEmpty.data) && checkEmpty.data.length === 0;

    const deletePassed = singleDelPassed && gonePassed && clearAllPassed && isEmpty;
    printCheck(5, 'DELETE /api/history/:id and DELETE /api/history clear scans correctly', deletePassed,
      `Single deleted: ${singleDelPassed}, Cleared count: ${delAll.data ? delAll.data.deletedCount : 0}`);

    // Check 6: Input validation (empty, too long, bad deviceId) returns 400
    const emptyText = await request('POST', '/api/analyze/message', { text: '', deviceId: deviceIdA });
    const tooLongText = await request('POST', '/api/analyze/message', { text: 'a'.repeat(2001), deviceId: deviceIdA });
    const badDevice = await request('POST', '/api/analyze/message', { text: 'Hello', deviceId: 'not-a-valid-uuid' });
    const emptyUrl = await request('POST', '/api/analyze/url', { url: '', deviceId: deviceIdA });
    const badDeviceHistory = await request('GET', '/api/history?deviceId=xyz');

    const validationPassed = emptyText.status === 400 &&
                             tooLongText.status === 400 &&
                             badDevice.status === 400 &&
                             emptyUrl.status === 400 &&
                             badDeviceHistory.status === 400;

    printCheck(6, 'Invalid input (empty text/url, text > 2000 chars, non-UUID deviceId) returns 400', validationPassed,
      `Statuses: emptyText=${emptyText.status}, tooLong=${tooLongText.status}, badDevice=${badDevice.status}, emptyUrl=${emptyUrl.status}`);

  } catch (err) {
    console.error('Unexpected test error:', err);
  } finally {
    await stopServer();
  }

  console.log('\n====================================================');
  console.log(`E2E Summary: ${checksPassed}/${totalChecks} Checks Passed`);
  console.log('====================================================');

  if (checksPassed === totalChecks) {
    console.log('All E2E checks passed successfully!\n');
    process.exit(0);
  } else {
    console.error('Some E2E checks failed.\n');
    process.exit(1);
  }
}

runE2ETests();

