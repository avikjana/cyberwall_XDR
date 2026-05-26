const Traffic = require('../models/traffic');

exports.getTrafficLogs = async (req, res) => {
  try {
    const { protocol, limit = 100 } = req.query;
    const filter = {};

    if (protocol) {
      filter.protocol = protocol;
    }

    const traffic = await Traffic.find(filter)
      .sort({ timestamp: -1 })
      .limit(parseInt(limit));

    res.status(200).json({ success: true, count: traffic.length, data: traffic });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

exports.logTraffic = async (req, res) => {
  try {
    const trafficEntry = await Traffic.create(req.body);

    if (global.io) {
      global.io.emit('new_traffic', trafficEntry);
    }

    res.status(201).json({ success: true, data: trafficEntry });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};
