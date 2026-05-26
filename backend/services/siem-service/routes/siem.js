const express = require('express');
const router = express.Router();
const siemController = require('../controllers/siemController');
const { protect } = require('../../../shared/authMiddleware');

// SIEM Search Endpoint
router.get('/search', protect, siemController.searchEvents);

// ClickHouse Dashboard Aggregations
router.get('/analytics/overview', protect, siemController.getOverviewStats);
router.get('/analytics/protocols', protect, siemController.getProtocolDistribution);
router.get('/analytics/attackers', protect, siemController.getTopAttackers);
router.get('/analytics/severity', protect, siemController.getThreatSeverityDistribution);
router.get('/analytics/timeline', protect, siemController.getTrafficTimeline);
router.get('/analytics/trends', protect, siemController.getDetectionTrends);

module.exports = router;
