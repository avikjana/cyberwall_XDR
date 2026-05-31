const Rule = require('../models/rule');
const { publishEvent } = require('../config/redis');
const { logAuditEvent } = require('../../shared/auditLogger');
const dns = require('dns').promises;

// Helper to resolve IP/Domain in background
async function resolveDns(ipOrDomain, type) {
  let resolvedDomain = 'N/A';
  let resolvedIp = 'N/A';

  if (type === 'IP') {
    try {
      const hostnames = await dns.reverse(ipOrDomain);
      if (hostnames && hostnames.length > 0) {
        resolvedDomain = hostnames[0];
      }
    } catch (err) {
      console.error(`Reverse DNS lookup failed for ${ipOrDomain}:`, err.message);
      resolvedDomain = 'N/A';
    }
  } else if (type === 'DOMAIN') {
    try {
      const addresses = await dns.resolve4(ipOrDomain);
      if (addresses && addresses.length > 0) {
        resolvedIp = addresses[0];
      }
    } catch (err) {
      try {
        const lookup = await dns.lookup(ipOrDomain);
        if (lookup && lookup.address) {
          resolvedIp = lookup.address;
        }
      } catch (err2) {
        console.error(`DNS lookup failed for domain ${ipOrDomain}:`, err2.message);
        resolvedIp = 'N/A';
      }
    }
  }

  return { resolvedDomain, resolvedIp };
}

exports.getRules = async (req, res) => {
  try {
    const rules = await Rule.find({ status: 'active' }).sort({ createdAt: -1 });

    // Background self-healing retroactive lookup for existing active rules lacking resolved info
    rules.forEach(async (rule) => {
      if ((rule.type === 'IP' && (!rule.resolvedDomain || rule.resolvedDomain === 'N/A')) ||
          (rule.type === 'DOMAIN' && (!rule.resolvedIp || rule.resolvedIp === 'N/A'))) {
        try {
          const { resolvedDomain, resolvedIp } = await resolveDns(rule.ip, rule.type);
          let updated = false;
          if (rule.type === 'IP' && resolvedDomain !== 'N/A') {
            rule.resolvedDomain = resolvedDomain;
            updated = true;
          } else if (rule.type === 'DOMAIN' && resolvedIp !== 'N/A') {
            rule.resolvedIp = resolvedIp;
            updated = true;
          }
          if (updated) {
            await Rule.updateOne({ _id: rule._id }, { 
              resolvedDomain: rule.resolvedDomain, 
              resolvedIp: rule.resolvedIp 
            });
          }
        } catch (err) {
          console.error(`Background resolution failed for rule ${rule._id}:`, err);
        }
      }
    });

    res.status(200).json({ success: true, count: rules.length, data: rules });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

exports.blockIp = async (req, res) => {
  try {
    const { ip, type, reason, duration } = req.body;
    if (!ip || !reason) {
      logAuditEvent('BLOCK_IP', req.user, ip, 'FAILURE', { error: 'Target and reason are required' });
      return res.status(400).json({ success: false, error: 'Target and reason are required' });
    }

    let expiresAt = null;
    if (duration) {
      expiresAt = new Date(Date.now() + duration * 60000);
    }

    let rule = await Rule.findOne({ ip });
    const ruleType = type || 'IP';

    const { resolvedDomain, resolvedIp } = await resolveDns(ip, ruleType);

    if (rule) {
      rule.status = 'active';
      rule.reason = reason;
      rule.type = ruleType;
      rule.expiresAt = expiresAt;
      rule.resolvedDomain = resolvedDomain;
      rule.resolvedIp = resolvedIp;
      rule.addedBy = req.user ? req.user.username : 'SYSTEM';
      await rule.save();
    } else {
      rule = await Rule.create({
        ip,
        type: ruleType,
        reason,
        expiresAt,
        addedBy: req.user ? req.user.username : 'SYSTEM',
        action: 'BLOCK',
        status: 'active',
        resolvedDomain,
        resolvedIp
      });
    }

    // Publish to Redis Pub/Sub so WebSocket Service broadcasts to Firewall Engine
    publishEvent('block_ip', { ip, type: ruleType, action: 'BLOCK' });
    logAuditEvent('BLOCK_IP', req.user, ip, 'SUCCESS', { reason, duration, type: ruleType, resolvedDomain, resolvedIp });

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
      return res.status(404).json({ success: false, error: 'Active block rule not found for this target' });
    }

    // Publish to Redis Pub/Sub with target type
    publishEvent('unblock_ip', { ip, type: rule.type, action: 'UNBLOCK' });
    logAuditEvent('UNBLOCK_IP', req.user, ip, 'SUCCESS');

    res.status(200).json({ success: true, data: rule });
  } catch (error) {
    logAuditEvent('UNBLOCK_IP', req.user, req.params.ip, 'FAILURE', { error: error.message });
    res.status(500).json({ success: false, error: error.message });
  }
};
