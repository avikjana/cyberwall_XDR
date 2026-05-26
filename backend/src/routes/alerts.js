const express = require('express');
const { getAlerts, createAlert, acknowledgeAlert, resolveAlert } = require('../controllers/alertController');
const { protect, authorize } = require('../middleware/auth');

const router = express.Router();

router.get('/', protect, getAlerts);
router.post('/', createAlert); // Engine creates alerts directly (or add simple custom key validation in production)
router.put('/:id/acknowledge', protect, acknowledgeAlert);
router.put('/:id/resolve', protect, resolveAlert);

module.exports = router;
