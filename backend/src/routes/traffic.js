const express = require('express');
const { getTrafficLogs, logTraffic } = require('../controllers/trafficController');
const { protect } = require('../middleware/auth');

const router = express.Router();

router.get('/', protect, getTrafficLogs);
router.post('/', logTraffic); // Internal engine traffic logging

module.exports = router;
