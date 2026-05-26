const Rule = require('../models/rule');
const { publishEvent } = require('../config/redis');
const { logAuditEvent } = require('../../shared/auditLogger');

exports.getRules = async (req, res) => {
  try {
    const rules = await Rule.find({ status: 'active' }).sort({ createdAt: -1 });
    res.status(200).json({ success: true, count: rules.length, data: rules });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

exports.blockIp = async (req, res) => {
  try {
    const { ip, reason, duration } = req.body;
    if (!ip || !reason) {
      logAuditEvent('BLOCK_IP', req.user, ip, 'FAILURE', { error: 'IP and reason are required' });
      return res.status(400).json({ success: false, error: 'IP and reason are required' });
    }

    let expiresAt = null;
    if (duration) {
      expiresAt = new Date(Date.now() + duration * 60000);
    }

    let rule = await Rule.findOne({ ip });

    if (rule) {
      rule.status = 'active';
      rule.reason = reason;
      rule.expiresAt = expiresAt;
      rule.addedBy = req.user ? req.user.username : 'SYSTEM';
      await rule.save();
    } else {
      rule = await Rule.create({
        ip,
        reason,
        expiresAt,
        addedBy: req.user ? req.user.username : 'SYSTEM',
        action: 'BLOCK',
        status: 'active'
      });
    }

    // Publish to Redis Pub/Sub so WebSocket Service broadcasts to Firewall Engine
    publishEvent('block_ip', { ip, action: 'BLOCK' });
    logAuditEvent('BLOCK_IP', req.user, ip, 'SUCCESS', { reason, duration });

    res.status(201).json({ success: true, data: rule });
  } catch (error) {
    logAuditEvent('BLOCK_IP', req.user, req.body.ip, 'FAILURE', { error: error.message });
    res.status(500).json({ success: false, error: error.message });
  }
};

exports.unblockIp = async (req, res) => {
  try {
    const { ip } = req.params;
    const rule = await Rule.findOneAndUpdate(
      { ip, status: 'active' },
      { status: 'removed' },
      { new: true }
    );

    if (!rule) {
      logAuditEvent('UNBLOCK_IP', req.user, ip, 'FAILURE', { error: 'Active block rule not found' });
      return res.status(404).json({ success: false, error: 'Active block rule not found for this IP' });
    }

    // Publish to Redis Pub/Sub
    publishEvent('unblock_ip', { ip, action: 'UNBLOCK' });
    logAuditEvent('UNBLOCK_IP', req.user, ip, 'SUCCESS');

    res.status(200).json({ success: true, data: rule });
  } catch (error) {
    logAuditEvent('UNBLOCK_IP', req.user, req.params.ip, 'FAILURE', { error: error.message });
    res.status(500).json({ success: false, error: error.message });
  }
};
