const Alert = require('../models/alert');

exports.getAlerts = async (req, res) => {
  try {
    const { status, severity, threatType, page = 1, limit = 50 } = req.query;
    const filter = {};
    const parsedLimit = Number(limit);
    const parsedPage = Number(page);

    if (status) filter.status = status;
    if (severity) filter.severity = severity;
    if (threatType) filter.threatType = threatType;

    const skipIndex = (parsedPage - 1) * parsedLimit;

    // Run find + count in parallel instead of sequentially
    const [alerts, total] = await Promise.all([
      Alert.find(filter)
        .sort({ timestamp: -1 })
        .limit(parsedLimit)
        .skip(skipIndex)
        .lean(),  // Return plain JS objects — ~3x faster serialization
      Alert.countDocuments(filter)
    ]);

    res.status(200).json({
      success: true,
      count: alerts.length,
      totalPages: Math.ceil(total / parsedLimit),
      currentPage: parsedPage,
      data: alerts
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

exports.createAlert = async (req, res) => {
  try {
    // Internal endpoint for firewall engine
    const alert = await Alert.create(req.body);

    // Broadcast via global Socket.io client if available (will bind in server.js)
    if (global.io) {
      global.io.to('soc_channel').emit('new_alert', alert);
    }

    res.status(201).json({ success: true, data: alert });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

exports.acknowledgeAlert = async (req, res) => {
  try {
    const { notes } = req.body;
    const alert = await Alert.findByIdAndUpdate(
      req.params.id,
      {
        status: 'acknowledged',
        notes: notes || 'Acknowledged by SOC Analyst',
        acknowledgedBy: req.user.id
      },
      { new: true }
    ).lean();

    if (!alert) {
      return res.status(404).json({ success: false, error: 'Alert not found' });
    }

    if (global.io) {
      global.io.to('soc_channel').emit('alert_updated', alert);
    }

    res.status(200).json({ success: true, data: alert });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

exports.resolveAlert = async (req, res) => {
  try {
    const { notes } = req.body;
    const alert = await Alert.findByIdAndUpdate(
      req.params.id,
      {
        status: 'resolved',
        notes: notes || 'Resolved'
      },
      { new: true }
    ).lean();

    if (!alert) {
      return res.status(404).json({ success: false, error: 'Alert not found' });
    }

    if (global.io) {
      global.io.to('soc_channel').emit('alert_updated', alert);
    }

    res.status(200).json({ success: true, data: alert });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};
