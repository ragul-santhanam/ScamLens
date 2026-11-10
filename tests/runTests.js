/**
 * ScamLens Unit & Benchmark Test Runner
 * Evaluates rule accuracy against 20 messages (10 scam, 10 genuine) and 8 URLs (4 suspicious, 4 legitimate).
 */
const path = require('path');
const fs = require('fs');

const { analyzeMessage } = require('../shared/messageAnalyzer');
const { analyzeUrl } = require('../shared/urlAnalyzer');

const samplesPath = path.join(__dirname, 'samples.json');
const samples = JSON.parse(fs.readFileSync(samplesPath, 'utf8'));

console.log('====================================================');
console.log('       ScamLens Rule Accuracy Benchmark');
console.log('====================================================\n');

let totalTests = 0;
let passedTests = 0;
const failures = [];

function checkResult(id, type, input, expected, actualResult) {
  totalTests++;
  const actualRisk = actualResult.riskLevel;
  const score = actualResult.score;

  let pass = false;
  if (expected === 'Low Risk') {
    // Genuine items must strictly score Low Risk (score < 25)
    pass = actualRisk === 'Low Risk';
  } else if (expected === 'High Risk') {
    // High risk expected: Suspicious or High Risk is acceptable, preferably High Risk
    pass = actualRisk === 'High Risk' || actualRisk === 'Suspicious';
  } else if (expected === 'Suspicious') {
    pass = actualRisk === 'Suspicious' || actualRisk === 'High Risk';
  }

  const icon = pass ? '✓ PASS' : '✗ FAIL';
  const firedNames = (actualResult.firedRules || []).map(r => r.id).join(', ') || 'None';

  console.log(`[${icon}] ${id} (${type})`);
  console.log(`   Preview: "${actualResult.maskedPreview}"`);
  console.log(`   Expected: ${expected} | Actual: ${actualRisk} (Score: ${score})`);
  console.log(`   Fired Rules: ${firedNames}`);

  if (pass) {
    passedTests++;
  } else {
    failures.push({ id, type, expected, actual: actualRisk, score, firedNames });
  }
  console.log('');
}

// 1. Scam Messages
console.log('--- Evaluating Scam Messages (Target: Suspicious / High Risk) ---');
samples.scamMessages.forEach(item => {
  const result = analyzeMessage(item.text);
  checkResult(item.id, 'Scam Msg', item.text, item.expectedRisk, result);
});

// 2. Genuine Messages
console.log('--- Evaluating Genuine Messages (Target: Low Risk) ---');
samples.genuineMessages.forEach(item => {
  const result = analyzeMessage(item.text);
  checkResult(item.id, 'Genuine Msg', item.text, item.expectedRisk, result);
});

// 3. Suspicious URLs
console.log('--- Evaluating Suspicious URLs (Target: Suspicious / High Risk) ---');
samples.suspiciousUrls.forEach(item => {
  const result = analyzeUrl(item.url);
  checkResult(item.id, 'Suspicious URL', item.url, item.expectedRisk, result);
});

// 4. Legitimate URLs
console.log('--- Evaluating Legitimate URLs (Target: Low Risk) ---');
samples.legitimateUrls.forEach(item => {
  const result = analyzeUrl(item.url);
  checkResult(item.id, 'Legit URL', item.url, item.expectedRisk, result);
});

// Summary
const accuracy = Math.round((passedTests / totalTests) * 100);
console.log('====================================================');
console.log(`Results: ${passedTests}/${totalTests} Passed (${accuracy}% Accuracy)`);
console.log('====================================================');

if (failures.length > 0) {
  console.error('\nFailures Detected:');
  failures.forEach(f => {
    console.error(`- ${f.id} (${f.type}): Expected ${f.expected}, Got ${f.actual} (Score: ${f.score}) [Rules: ${f.firedNames}]`);
  });
  process.exit(1);
} else {
  console.log('\nAll benchmark tests passed with 100% accuracy!');
  process.exit(0);
}

