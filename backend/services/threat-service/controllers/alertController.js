const Alert = require('../models/alert');
const { publishEvent } = require('../config/redis');
const { publishToKafka } = require('../config/kafka');
const { logAuditEvent } = require('../../shared/auditLogger');

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

    const [alerts, total] = await Promise.all([
      Alert.find(filter)
        .sort({ timestamp: -1 })
        .limit(parsedLimit)
        .skip(skipIndex)
        .lean(),
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
    const alert = await Alert.create(req.body);

    // Publish to Redis Pub/Sub so WebSocket Service broadcasts to SOC
    publishEvent('new_alert', alert);

    // Publish to Kafka for SIEM pipeline ingestion
    publishToKafka('cyberwall-alerts', alert);

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
      logAuditEvent('ACKNOWLEDGE_ALERT', req.user, req.params.id, 'FAILURE', { error: 'Alert not found' });
      return res.status(404).json({ success: false, error: 'Alert not found' });
    }

    logAuditEvent('ACKNOWLEDGE_ALERT', req.user, alert._id, 'SUCCESS', { notes });
    publishEvent('alert_updated', alert);

    res.status(200).json({ success: true, data: alert });
  } catch (error) {
    logAuditEvent('ACKNOWLEDGE_ALERT', req.user, req.params.id, 'FAILURE', { error: error.message });
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
      logAuditEvent('RESOLVE_ALERT', req.user, req.params.id, 'FAILURE', { error: 'Alert not found' });
      return res.status(404).json({ success: false, error: 'Alert not found' });
    }

    logAuditEvent('RESOLVE_ALERT', req.user, alert._id, 'SUCCESS', { notes });
    publishEvent('alert_updated', alert);

    res.status(200).json({ success: true, data: alert });
  } catch (error) {
    logAuditEvent('RESOLVE_ALERT', req.user, req.params.id, 'FAILURE', { error: error.message });
    res.status(500).json({ success: false, error: error.message });
  }
};
