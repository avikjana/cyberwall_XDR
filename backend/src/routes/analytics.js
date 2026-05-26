const express = require('express');
const {
  getOverviewStats,
  getProtocolDistribution,
  getTopAttackers,
  getThreatSeverityDistribution,
  getTrafficTimeline
} = require('../controllers/analyticsController');
const { protect } = require('../middleware/auth');

const router = express.Router();

router.get('/overview', protect, getOverviewStats);
router.get('/protocols', protect, getProtocolDistribution);
router.get('/top-attackers', protect, getTopAttackers);
router.get('/severity', protect, getThreatSeverityDistribution);
router.get('/timeline', protect, getTrafficTimeline);

module.exports = router;
