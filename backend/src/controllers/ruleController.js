const Rule = require('../models/rule');

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
      return res.status(400).json({ success: false, error: 'IP and reason are required' });
    }

    let expiresAt = null;
    if (duration) {
      expiresAt = new Date(Date.now() + duration * 60000); // duration in minutes
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

    // Broadcast update so Firewall Engine syncs rules
    if (global.io) {
      global.io.emit('block_ip', { ip, action: 'BLOCK' });
    }

    res.status(201).json({ success: true, data: rule });
  } catch (error) {
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
      return res.status(404).json({ success: false, error: 'Active block rule not found for this IP' });
    }

    // Broadcast update to Firewall Engine
    if (global.io) {
      global.io.emit('unblock_ip', { ip, action: 'UNBLOCK' });
    }

    res.status(200).json({ success: true, data: rule });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};
