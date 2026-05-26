const express = require('express');
const { getAlerts, createAlert, acknowledgeAlert, resolveAlert } = require('../controllers/alertController');
const { protect } = require('../../shared/authMiddleware');

const router = express.Router();

router.get('/', protect, getAlerts);
router.post('/', createAlert);
router.put('/:id/acknowledge', protect, acknowledgeAlert);
router.put('/:id/resolve', protect, resolveAlert);

module.exports = router;
