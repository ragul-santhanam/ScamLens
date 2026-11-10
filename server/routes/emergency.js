const express = require('express');
const router = express.Router();

const emergencyController = require('../controllers/emergencyController');
const { optionalAuth } = require('../middleware/auth');
const { analyzeLimiter } = require('../middleware/rateLimit');

router.use(optionalAuth);

router.get('/guidance', emergencyController.getGuidance);
router.post('/session', analyzeLimiter, emergencyController.saveEmergencySession);
router.get('/history', emergencyController.getEmergencyHistory);

module.exports = router;

