/**
 * ScamLens Shared Configuration
 * Used by both Node.js backend and on-device Capacitor frontend engine.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.ScamLensConfig = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  return {
    appName: 'ScamLens',
    tagline: 'See Through Scams. Stay Safe.',

    // Scoring & Risk Thresholds
    thresholds: {
      low: {
        min: 0,
        max: 24,
        label: 'Low Risk',
        indicatorCategory: 'Low Risk Indicators',
        note: 'No major risk indicators found',
        color: '#16A34A'
      },
      suspicious: {
        min: 25,
        max: 59,
        label: 'Suspicious',
        indicatorCategory: 'Medium Risk Indicators',
        note: 'Exercise high caution. Several red flags detected',
        color: '#D97706'
      },
      high: {
        min: 60,
        max: 100,
        label: 'High Risk',
        indicatorCategory: 'High Risk Indicators',
        note: 'Danger: Strong scam indicators found. Do not interact',
        color: '#B3261E'
      }
    },

    // Mandatory Disclaimer
    disclaimer: 'ScamLens gives risk indicators, not guaranteed verdicts. Always verify independently through official channels before acting.',

    // Tailored Recommendations
    recommendations: {
      low: [
        'No immediate scam signals were detected, but always stay vigilant.',
        'Never share passwords, OTPs, or UPI PINs with anyone over call or text.',
        'Verify senders through official apps or bookmarked websites.'
      ],
      suspicious: [
        'Do not click any links, open attachments, or dial callback numbers mentioned in the message.',
        'Never share OTP, PIN, CVV, or banking credentials. No legitimate institution requests these.',
        'Verify the claim directly through official customer service channels or bank branches.',
        'If suspicious of financial fraud, dial 1930 or visit cybercrime.gov.in.'
      ],
      high: [
        'DO NOT respond, click any links, scan QR codes, or make any payment.',
        'Never share OTP, PIN, CVV, or Aadhaar/PAN details. This is an urgent red flag.',
        'Immediately block the sender and report the message as spam/phishing.',
        'If you already sent money or shared credentials, contact your bank immediately to freeze your account and dial 1930.',
        'File an official cybercrime report at cybercrime.gov.in.'
      ]
    },

    // Limits
    limits: {
      maxTextLength: 2000,
      maxUrlLength: 2048,
      maxMaskedPreviewLength: 60,
      historyLimit: 50,
      offlineTimeoutMs: 5000
    }
  };
}));

