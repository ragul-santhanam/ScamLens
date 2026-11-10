const express = require('express');
const router = express.Router();
const { ScanService } = require('../models/Scan');

/**
 * GET /api/health
 * Returns service status and database connectivity
 */
router.get('/', (req, res) => {
  const isConnected = ScanService.isDbConnected();
  res.json({
    status: 'ok',
    db: isConnected ? 'connected' : 'disconnected'
  });
});

module.exports = router;

