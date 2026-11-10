const express = require('express');
const multer = require('multer');
const router = express.Router();

const paymentController = require('../controllers/paymentController');
const { optionalAuth } = require('../middleware/auth');
const { analyzeLimiter } = require('../middleware/rateLimit');

const ALLOWED_MIMES = ['image/jpeg', 'image/jpg', 'image/png'];

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024 // 5 MB max
  },
  fileFilter: (req, file, cb) => {
    const mime = (file.mimetype || '').toLowerCase();
    const extMatch = /\.(jpe?g|png)$/i.test(file.originalname || '');
    if (!ALLOWED_MIMES.includes(mime) && !extMatch) {
      const err = new Error('Unsupported file format. Please upload a PNG, JPG, or JPEG screenshot.');
      err.status = 400;
      return cb(err);
    }
    cb(null, true);
  }
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
          return res.status(400).json({
            error: err.code === 'LIMIT_FILE_SIZE'
              ? 'File size exceeds 5 MB limit.'
              : (err.message || 'Invalid image file upload.')
          });
        }
        next();
      });
    }
    next();
  },
  paymentController.analyzePayment
);

router.get('/history', paymentController.getPaymentHistory);

module.exports = router;

