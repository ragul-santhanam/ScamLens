const express = require('express');
const router = express.Router();

const { analyzeLimiter } = require('../middleware/rateLimit');
const { optionalAuth } = require('../middleware/auth');
const { validateMessagePayload, validateUrlPayload } = require('../middleware/validate');
const { analyzeMessage } = require('../../shared/messageAnalyzer');
const { analyzeUrlWithIdentity } = require('../services/urlIdentityService');
const { ScanService } = require('../models/Scan');
const { MessageScanService } = require('../models/MessageScan');
const { URLScanService } = require('../models/URLScan');

// Apply 30 requests/minute rate limit and optional JWT auth to all analyze endpoints
router.use(analyzeLimiter);
router.use(optionalAuth);

/**
 * POST /api/analyze/message
 * Evaluates message text for scam indicators and records scan
 */
router.post('/message', validateMessagePayload, async (req, res, next) => {
  try {
    const text = req.validatedText;
    const deviceId = req.validatedDeviceId;
    const userId = req.user ? req.user.id : null;

    // Run core engine
    const analysis = analyzeMessage(text);

    // Save scan to unified Scan collection + MessageScan collection
    const [saved] = await Promise.all([
      ScanService.create({
        userId,
        deviceId,
        type: 'message',
        riskLevel: analysis.riskLevel,
        riskCategory: analysis.riskCategory,
        score: analysis.score,
        firedRules: analysis.firedRules,
        maskedPreview: analysis.maskedPreview
      }),
      MessageScanService.create({
        userId,
        deviceId,
        maskedPreview: analysis.maskedPreview,
        riskLevel: analysis.riskLevel,
        riskCategory: analysis.riskCategory,
        score: analysis.score,
        firedRules: analysis.firedRules,
        actions: analysis.actions
      })
    ]);

    res.json({
      scanId: saved ? saved._id : null,
      type: 'message',
      score: analysis.score,
      riskLevel: analysis.riskLevel,
      riskCategory: analysis.riskCategory,
      firedRules: analysis.firedRules,
      actions: analysis.actions,
      disclaimer: analysis.disclaimer,
      analyzedAt: analysis.analyzedAt
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/analyze/url
 * Evaluates URL for phishing, website identity, brand impersonation, and obfuscation
 */
router.post('/url', validateUrlPayload, async (req, res, next) => {
  try {
    const url = req.validatedUrl;
    const deviceId = req.validatedDeviceId;
    const userId = req.user ? req.user.id : null;

    // Run enhanced URL & Website Identity engine
    const analysis = await analyzeUrlWithIdentity(url);

    // Save scan to unified Scan collection + URLScan collection
    const [saved] = await Promise.all([
      ScanService.create({
        userId,
        deviceId,
        type: 'url',
        riskLevel: analysis.riskLevel,
        riskCategory: analysis.riskCategory,
        score: analysis.score,
        firedRules: analysis.firedRules,
        maskedPreview: analysis.maskedPreview,
        details: {
          enteredUrl: analysis.enteredUrl,
          normalizedDomain: analysis.normalizedDomain,
          identityReport: analysis.identityReport
        }
      }),
      URLScanService.create({
        userId,
        deviceId,
        maskedPreview: analysis.maskedPreview,
        normalizedDomain: analysis.normalizedDomain,
        identityReport: analysis.identityReport,
        riskLevel: analysis.riskLevel,
        riskCategory: analysis.riskCategory,
        score: analysis.score,
        firedRules: analysis.firedRules,
        actions: analysis.actions
      })
    ]);

    res.json({
      scanId: saved ? saved._id : null,
      type: 'url',
      score: analysis.score,
      riskLevel: analysis.riskLevel,
      riskCategory: analysis.riskCategory,
      firedRules: analysis.firedRules,
      actions: analysis.actions,
      disclaimer: analysis.disclaimer,
      enteredUrl: analysis.enteredUrl,
      normalizedDomain: analysis.normalizedDomain,
      identityReport: analysis.identityReport,
      analyzedAt: analysis.analyzedAt
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
