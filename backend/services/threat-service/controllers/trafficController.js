const Traffic = require('../models/traffic');
const { publishEvent } = require('../config/redis');
const { publishToKafka } = require('../config/kafka');

let _trafficBuffer = [];
const BATCH_SIZE = 100;
const FLUSH_INTERVAL_MS = 2000;

const _flushTrafficBuffer = async () => {
  if (_trafficBuffer.length === 0) return;

  const batch = _trafficBuffer;
  _trafficBuffer = [];

  try {
    const inserted = await Traffic.insertMany(batch, { ordered: false });

    // Publish to Kafka for SIEM pipeline ingestion
    publishToKafka('cyberwall-traffic', batch);

    // Publish the last entry to Redis Pub/Sub for real-time live map updates
    if (inserted.length > 0) {
      publishEvent('new_traffic', inserted[inserted.length - 1]);
    }
  } catch (error) {
    console.error(`[Threat Service] Traffic batch insert failed: ${error.message}`);
  }
};

setInterval(_flushTrafficBuffer, FLUSH_INTERVAL_MS);

exports.getTrafficLogs = async (req, res) => {
  try {
    const { protocol, limit = 100 } = req.query;
    const filter = {};

    if (protocol) {
      filter.protocol = protocol;
    }

    const traffic = await Traffic.find(filter)
      .sort({ timestamp: -1 })
      .limit(Number(limit))
      .lean();

    res.status(200).json({ success: true, count: traffic.length, data: traffic });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

exports.logTraffic = async (req, res) => {
  try {
    _trafficBuffer.push(req.body);

    if (_trafficBuffer.length >= BATCH_SIZE) {
      _flushTrafficBuffer();
    }

    res.status(201).json({ success: true, data: req.body });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

exports.logTrafficBatch = async (req, res) => {
  try {
    const { entries } = req.body;
    if (!entries || !Array.isArray(entries) || entries.length === 0) {
      return res.status(400).json({ success: false, error: 'entries array is required' });
    }

    _trafficBuffer.push(...entries);

    if (_trafficBuffer.length >= BATCH_SIZE) {
      _flushTrafficBuffer();
    }

    res.status(201).json({ success: true, count: entries.length });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};
