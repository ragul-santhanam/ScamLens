const express = require('express');
const router = express.Router();

const { optionalAuth } = require('../middleware/auth');
const { validateDeviceQuery } = require('../middleware/validate');
const { ScanService } = require('../models/Scan');
const { calculateScore } = require('../../shared/scoring');
const config = require('../../shared/config');

router.use(optionalAuth);
router.use(validateDeviceQuery);

/**
 * GET /api/history?deviceId=...
 * Returns last 50 scans for the authenticated user (or specified device), newest first
 */
router.get('/', async (req, res, next) => {
  try {
    const userId = req.user ? req.user.id : null;
    const deviceId = req.validatedDeviceId;
    const scans = await ScanService.findByOwner({ userId, deviceId }, config.limits.historyLimit || 50);

    const formatted = scans.map(s => ({
      _id: s._id,
      type: s.type,
      riskLevel: s.riskLevel,
      riskCategory: s.riskCategory || 'Low Risk Indicators',
      score: s.score,
      maskedPreview: s.maskedPreview,
      details: s.details || null,
      createdAt: s.createdAt
    }));

    res.json(formatted);
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/history/:id?deviceId=...
 * Returns full details and warning signs for a specific scan
 */
router.get('/:id', async (req, res, next) => {
  try {
    const id = req.params.id;
    const userId = req.user ? req.user.id : null;
    const deviceId = req.validatedDeviceId;

    const scan = await ScanService.findByIdAndOwner(id, { userId, deviceId });
    if (!scan) {
      return res.status(404).json({ error: 'Scan record not found.' });
    }

    const scored = calculateScore(scan.firedRules);

    res.json({
      _id: scan._id,
      type: scan.type,
      riskLevel: scan.riskLevel,
      riskCategory: scan.riskCategory || scored.riskCategory,
      score: scan.score,
      firedRules: scan.firedRules || [],
      maskedPreview: scan.maskedPreview,
      details: scan.details || null,
      identityReport: scan.details && scan.details.identityReport ? scan.details.identityReport : null,
      extractedInfo: scan.details && scan.details.extractedInfo ? scan.details.extractedInfo : null,
      qrDetails: scan.details && scan.details.qrDetails ? scan.details.qrDetails : null,
      createdAt: scan.createdAt,
      actions: scored.actions,
      disclaimer: config.disclaimer
    });
  } catch (err) {
    next(err);
  }
});

/**
 * DELETE /api/history/:id?deviceId=...
 * Deletes a single scan belonging to the user or device
 */
router.delete('/:id', async (req, res, next) => {
  try {
    const id = req.params.id;
    const userId = req.user ? req.user.id : null;
    const deviceId = req.validatedDeviceId;

    const deleted = await ScanService.deleteByIdAndOwner(id, { userId, deviceId });
    if (!deleted) {
      return res.status(404).json({ error: 'Scan record not found or already deleted.' });
    }

    res.json({
      success: true,
      message: 'Scan deleted successfully.'
    });
  } catch (err) {
    next(err);
  }
});

/**
 * DELETE /api/history?deviceId=...
 * Clears all scan history for the authenticated user or specified device
 */
router.delete('/', async (req, res, next) => {
  try {
    const userId = req.user ? req.user.id : null;
    const deviceId = req.validatedDeviceId;
    const deletedCount = await ScanService.clearAllByOwner({ userId, deviceId });

    res.json({
      success: true,
      deletedCount,
      message: 'All scan records have been cleared.'
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
