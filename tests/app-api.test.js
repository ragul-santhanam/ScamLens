/**
 * ScamLens App-to-API Integration Test
 * Verifies that app/www/js/api.js functions correctly when imported in Node.js
 * and executes live requests against the local Express server.
 */
const { randomUUID } = require('crypto');
const { startServer, stopServer } = require('../server/app');
const api = require('../app/www/js/api');

const TEST_PORT = 3200;
let checksPassed = 0;
let totalChecks = 0;

function printResult(testName, passed, info = '') {
  totalChecks++;
  if (passed) {
    checksPassed++;
    console.log(`[PASS] ${testName}`);
    if (info) console.log(`       ${info}`);
  } else {
    console.error(`[FAIL] ${testName}`);
    if (info) console.error(`       Error: ${info}`);
  }
}

async function runApiIntegrationTests() {
  console.log('====================================================');
  console.log('      ScamLens App-to-API Client Integration Tests');
  console.log('====================================================\n');

  try {
    await startServer(TEST_PORT);
    api.setBaseUrl(`http://localhost:${TEST_PORT}`);
  } catch (err) {
    console.error('Failed to start server on port', TEST_PORT, err);
    process.exit(1);
  }

  const deviceId = randomUUID();
  let firstScanId = null;

  try {
    // 1. Analyze a Message
    const msgText = 'Dear user, your bank account is blocked due to KYC. Update pan card immediately: https://sbi-kyc.xyz/login';
    const msgResult = await api.analyzeMessage(msgText, deviceId);
    const msgPassed = Boolean(msgResult && msgResult.scanId && msgResult.riskLevel && msgResult.score >= 0 && Array.isArray(msgResult.actions));
    firstScanId = msgResult ? msgResult.scanId : null;
    printResult('1. Analyze Message via API Client', msgPassed,
      `Risk: ${msgResult.riskLevel}, Score: ${msgResult.score}, ScanId: ${msgResult.scanId}`);

    // 2. Analyze a URL
    const urlText = 'http://paytm-secure-login.xyz/kyc-update';
    const urlResult = await api.analyzeUrl(urlText, deviceId);
    const urlPassed = Boolean(urlResult && urlResult.scanId && urlResult.riskLevel === 'High Risk' && urlResult.score >= 60);
    printResult('2. Analyze URL via API Client', urlPassed,
      `Risk: ${urlResult.riskLevel}, Score: ${urlResult.score}, ScanId: ${urlResult.scanId}`);

    // 3. Fetch History
    const historyList = await api.getHistory(deviceId);
    const historyPassed = Array.isArray(historyList) && historyList.length === 2 &&
                          historyList.some(item => item._id.toString() === firstScanId.toString());
    printResult('3. Fetch History for Device', historyPassed,
      `Retrieved ${historyList.length} scans for deviceId: ${deviceId}`);

    // 4. Delete One Scan
    const deleteRes = await api.deleteScan(firstScanId, deviceId);
    const afterDeleteHistory = await api.getHistory(deviceId);
    const deletePassed = Boolean(deleteRes && deleteRes.success) && afterDeleteHistory.length === 1;
    printResult('4. Delete One Scan via API Client', deletePassed,
      `Deleted scanId: ${firstScanId}. Remaining items: ${afterDeleteHistory.length}`);

    // 5. Clear All History
    const clearRes = await api.clearHistory(deviceId);
    const finalHistory = await api.getHistory(deviceId);
    const clearPassed = Boolean(clearRes && clearRes.success) && finalHistory.length === 0;
    printResult('5. Clear All Scans via API Client', clearPassed,
      `Cleared count: ${clearRes ? clearRes.deletedCount : 0}. Final history count: ${finalHistory.length}`);

  } catch (err) {
    console.error('API Client test exception:', err);
  } finally {
    await stopServer();
  }

  console.log('\n====================================================');
  console.log(`Integration Summary: ${checksPassed}/${totalChecks} Tests Passed`);
  console.log('====================================================');

  if (checksPassed === totalChecks) {
    console.log('All App-to-API client tests passed successfully!\n');
    process.exit(0);
  } else {
    console.error('Some App-to-API client tests failed.\n');
    process.exit(1);
  }
}

runApiIntegrationTests();

