const { analyzeQrContent, decodeQrFromImageBuffer } = require('../services/qrAnalyzerService');
const { QRScanService } = require('../models/QRScan');
const { ScanService } = require('../models/Scan');

/**
 * POST /api/qr/analyze
 * Accepts either { qrContent, deviceId } JSON or multipart form-data with 'image' file
 */
async function analyzeQr(req, res, next) {
  try {
    let rawContent = req.body && (req.body.qrContent || req.body.content || req.body.text);
    const deviceId = (req.body && req.body.deviceId) || 'authenticated-user-device';
    const userId = req.user ? req.user.id : null;

    if (!rawContent && req.file && req.file.buffer) {
      rawContent = decodeQrFromImageBuffer(req.file.buffer, req.file.mimetype || '');
    }

    if (!rawContent || typeof rawContent !== 'string' || !rawContent.trim()) {
      return res.status(400).json({
        error: 'QR code content is required. Scan a QR code or upload a clear QR image.'
      });
    }

    const analysis = await analyzeQrContent(rawContent);

    const [savedScan] = await Promise.all([
      ScanService.create({
        userId,
        deviceId,
        type: 'qr',
        riskLevel: analysis.riskLevel,
        riskCategory: analysis.riskCategory,
        score: analysis.score,
        firedRules: analysis.firedRules,
        maskedPreview: analysis.maskedPreview,
        details: {
          contentType: analysis.contentType,
          extractedUrl: analysis.extractedUrl,
          identityReport: analysis.identityReport || null,
          qrDetails: analysis.qrDetails
        }
      }),
      QRScanService.create({
        userId,
        deviceId,
        contentType: analysis.contentType,
        maskedPreview: analysis.maskedPreview,
        extractedUrl: analysis.extractedUrl,
        qrDetails: analysis.qrDetails,
        riskLevel: analysis.riskLevel,
        riskCategory: analysis.riskCategory,
        score: analysis.score,
        firedRules: analysis.firedRules,
        actions: analysis.actions
      })
    ]);

    res.json({
      scanId: savedScan ? savedScan._id : null,
      type: 'qr',
      contentType: analysis.contentType,
      extractedContent: analysis.extractedContent,
      extractedUrl: analysis.extractedUrl,
      normalizedDomain: analysis.normalizedDomain || null,
      identityReport: analysis.identityReport || null,
      qrDetails: analysis.qrDetails,
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
}

/**
 * GET /api/qr/history
 */
async function getQrHistory(req, res, next) {
  try {
    const userId = req.user ? req.user.id : null;
    const deviceId = req.query.deviceId || null;
    if (!userId && !deviceId) {
      return res.status(401).json({ error: 'Authentication or deviceId required to view QR history.' });
    }

    const history = await QRScanService.findByOwner({ userId, deviceId }, 50);
    res.json(history);
  } catch (err) {
    next(err);
  }
}

module.exports = {
  analyzeQr,
  getQrHistory
};

