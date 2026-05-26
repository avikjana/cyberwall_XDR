const Traffic = require('../models/traffic');

// ─── In-memory traffic buffer for batched inserts ────────────────────────────
let _trafficBuffer = [];
const BATCH_SIZE = 100;
const FLUSH_INTERVAL_MS = 2000;

// Background flush timer — writes accumulated traffic in bulk
const _flushTrafficBuffer = async () => {
  if (_trafficBuffer.length === 0) return;

  const batch = _trafficBuffer;
  _trafficBuffer = [];

  try {
    // insertMany with ordered:false allows partial success (doesn't abort on single validation failure)
    const inserted = await Traffic.insertMany(batch, { ordered: false });

    // Broadcast the last entry as a sample to connected clients (throttled)
    if (global.io && inserted.length > 0) {
      global.io.to('soc_channel').emit('new_traffic', inserted[inserted.length - 1]);
    }
  } catch (error) {
    // If bulk insert fails, log but don't crash — traffic is non-critical telemetry
    console.error(`Traffic batch insert failed: ${error.message}`);
  }
};

// Start the periodic flush timer
setInterval(_flushTrafficBuffer, FLUSH_INTERVAL_MS);

exports.getTrafficLogs = async (req, res) => {
  try {
    const { protocol, limit = 100 } = req.query;
    const filter = {};

    if (protocol) {
      filter.protocol = protocol;
    }

    // Use .lean() for read-only queries — returns plain JS objects, ~3x faster serialization
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
    // Buffer the entry instead of immediate DB write
    _trafficBuffer.push(req.body);

    // Flush immediately if buffer hits batch size threshold
    if (_trafficBuffer.length >= BATCH_SIZE) {
      // Don't await — flush asynchronously to keep response fast
      _flushTrafficBuffer();
    }

    res.status(201).json({ success: true, data: req.body });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

// Batch endpoint for the optimized firewall engine
exports.logTrafficBatch = async (req, res) => {
  try {
    const { entries } = req.body;
    if (!entries || !Array.isArray(entries) || entries.length === 0) {
      return res.status(400).json({ success: false, error: 'entries array is required' });
    }

    // Add all entries to buffer
    _trafficBuffer.push(...entries);

    // Flush if buffer exceeds threshold
    if (_trafficBuffer.length >= BATCH_SIZE) {
      _flushTrafficBuffer();
    }

    res.status(201).json({ success: true, count: entries.length });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};
