const { analyzePaymentScreenshot } = require('../services/paymentOcrService');
const { PaymentScreenshotScanService } = require('../models/PaymentScreenshotScan');
const { ScanService } = require('../models/Scan');

/**
 * POST /api/payment/analyze
 */
async function analyzePayment(req, res, next) {
  try {
    const userId = req.user ? req.user.id : null;
    const deviceId = (req.body && req.body.deviceId) || 'authenticated-user-device';
    const clientOcrHint = (req.body && req.body.ocrText) || '';

    let imageBuffer = null;
    let mimeType = '';

    if (req.file && req.file.buffer) {
      imageBuffer = req.file.buffer;
      mimeType = req.file.mimetype || '';
    } else if (req.body && req.body.imageBase64 && typeof req.body.imageBase64 === 'string') {
      const rawB64 = req.body.imageBase64.trim();
      const dataUriMatch = rawB64.match(/^data:([^;]+);base64,(.+)$/);
      if (dataUriMatch) {
        mimeType = dataUriMatch[1];
        imageBuffer = Buffer.from(dataUriMatch[2], 'base64');
      } else {
        mimeType = req.body.mimeType || '';
        imageBuffer = Buffer.from(rawB64, 'base64');
      }
    }

    if (!imageBuffer || imageBuffer.length === 0) {
      return res.status(400).json({
        error: 'Please upload a valid payment screenshot image (PNG, JPG, or JPEG).'
      });
    }

    if (imageBuffer.length > 5 * 1024 * 1024) {
      return res.status(400).json({
        error: 'Image file size exceeds the 5 MB limit.'
      });
    }

    const analysis = await analyzePaymentScreenshot(imageBuffer, mimeType, clientOcrHint);

    // Explicitly discard reference to raw image buffer after OCR processing
    imageBuffer = null;
    if (req.file) req.file.buffer = null;

    const [savedScan] = await Promise.all([
      ScanService.create({
        userId,
        deviceId,
        type: 'payment',
        riskLevel: analysis.riskLevel,
        riskCategory: analysis.riskCategory,
        score: analysis.score,
        firedRules: analysis.firedRules,
        maskedPreview: analysis.maskedPreview,
        details: {
          extractedInfo: analysis.extractedInfo,
          imageMeta: analysis.imageMeta
        }
      }),
      PaymentScreenshotScanService.create({
        userId,
        deviceId,
        utrNumber: analysis.utrNumber,
        maskedPreview: analysis.maskedPreview,
        extractedInfo: analysis.extractedInfo,
        imageMeta: analysis.imageMeta,
        riskLevel: analysis.riskLevel,
        riskCategory: analysis.riskCategory,
        score: analysis.score,
        firedRules: analysis.firedRules,
        actions: analysis.actions
      })
    ]);

    res.json({
      scanId: savedScan ? savedScan._id : null,
      type: 'payment',
      score: analysis.score,
      riskLevel: analysis.riskLevel,
      riskCategory: analysis.riskCategory,
      extractedInfo: analysis.extractedInfo,
      imageMeta: analysis.imageMeta,
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
 * GET /api/payment/history
 */
async function getPaymentHistory(req, res, next) {
  try {
    const userId = req.user ? req.user.id : null;
    const deviceId = req.query.deviceId || null;

    if (!userId && !deviceId) {
      return res.status(401).json({ error: 'Authentication or deviceId required to view payment scan history.' });
    }

    const history = await PaymentScreenshotScanService.findByOwner({ userId, deviceId }, 50);
    res.json(history);
  } catch (err) {
    next(err);
  }
}

module.exports = {
  analyzePayment,
  getPaymentHistory
};

