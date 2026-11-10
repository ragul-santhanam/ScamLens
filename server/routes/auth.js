const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { requireAuth } = require('../middleware/auth');
const { analyzeLimiter } = require('../middleware/rateLimit');

router.post('/signup', analyzeLimiter, authController.signup);
router.post('/login', analyzeLimiter, authController.login);
router.post('/logout', requireAuth, authController.logout);
router.post('/forgot-password', analyzeLimiter, authController.forgotPassword);
router.post('/reset-password', analyzeLimiter, authController.forgotPassword);
router.get('/me', requireAuth, authController.getMe);

module.exports = router;

