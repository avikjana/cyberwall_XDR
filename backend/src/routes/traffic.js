const express = require('express');
const { getTrafficLogs, logTraffic, logTrafficBatch } = require('../controllers/trafficController');
const { protect } = require('../middleware/auth');

const router = express.Router();

router.get('/', protect, getTrafficLogs);
router.post('/', logTraffic); // Internal engine traffic logging
router.post('/batch', logTrafficBatch); // Batch traffic logging from optimized engine

module.exports = router;
