const express = require('express');
const multer = require('multer');
const router = express.Router();

const qrController = require('../controllers/qrController');
const { optionalAuth } = require('../middleware/auth');
const { analyzeLimiter } = require('../middleware/rateLimit');

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 } // 5 MB limit
});

router.use(optionalAuth);

router.post(
  '/analyze',
  analyzeLimiter,
  (req, res, next) => {
    const contentType = req.headers['content-type'] || '';
    if (contentType.includes('multipart/form-data')) {
      return upload.single('image')(req, res, (err) => {
        if (err) {
          return res.status(400).json({ error: err.message || 'Invalid QR image upload.' });
        }
        next();
      });
    }
    next();
  },
  qrController.analyzeQr
);

router.get('/history', qrController.getQrHistory);

module.exports = router;

