const express = require('express');
const { getRules, blockIp, unblockIp } = require('../controllers/ruleController');
const { protect, authorize } = require('../../shared/authMiddleware');

const router = express.Router();

router.get('/', protect, getRules);
router.post('/block', protect, authorize('admin'), blockIp);
router.delete('/unblock/:ip', protect, authorize('admin'), unblockIp);

module.exports = router;
