const Alert = require('../models/alert');
const Rule = require('../models/rule');

exports.getAlerts = async (req, res) => {
  try {
    const { status, severity, threatType, page = 1, limit = 50 } = req.query;
    const filter = {};

    if (status) filter.status = status;
    if (severity) filter.severity = severity;
    if (threatType) filter.threatType = threatType;

    const skipIndex = (page - 1) * limit;
    const alerts = await Alert.find(filter)
      .sort({ timestamp: -1 })
      .limit(parseInt(limit))
      .skip(skipIndex);

    const total = await Alert.countDocuments(filter);

    res.status(200).json({
      success: true,
      count: alerts.length,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page),
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
      global.io.emit('new_alert', alert);
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
    );

    if (!alert) {
      return res.status(404).json({ success: false, error: 'Alert not found' });
    }

    if (global.io) {
      global.io.emit('alert_updated', alert);
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
    );

    if (!alert) {
      return res.status(404).json({ success: false, error: 'Alert not found' });
    }

    if (global.io) {
      global.io.emit('alert_updated', alert);
    }

    res.status(200).json({ success: true, data: alert });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};
