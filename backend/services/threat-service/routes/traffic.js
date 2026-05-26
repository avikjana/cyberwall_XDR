const express = require('express');
const { getTrafficLogs, logTraffic, logTrafficBatch } = require('../controllers/trafficController');
const { protect } = require('../../shared/authMiddleware');

const router = express.Router();

router.get('/', protect, getTrafficLogs);
router.post('/', logTraffic);
router.post('/batch', logTrafficBatch);

module.exports = router;
