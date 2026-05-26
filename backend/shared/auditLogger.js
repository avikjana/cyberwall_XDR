/**
 * Centralized Audit Logging Utility for CyberWall XDR.
 * Outputs structured JSON logs to stdout for enterprise log collection (ELK/Splunk/Loki).
 */

const logAuditEvent = (action, actor, target, status, details = {}) => {
  const auditRecord = {
    timestamp: new Date().toISOString(),
    action, // e.g. "BLOCK_IP", "UNBLOCK_IP", "RESOLVE_ALERT", "USER_LOGIN"
    actor: {
      id: actor?.id || 'system',
      username: actor?.username || 'system',
      role: actor?.role || 'system'
    },
    target: target || 'N/A', // e.g. IP address, Alert ID, Rule ID
    status: status || 'SUCCESS', // "SUCCESS" or "FAILURE"
    details: details || {}
  };

  // Structured stdout print for log collectors
  console.log(`[AUDIT_LOG] ${JSON.stringify(auditRecord)}`);
};

module.exports = { logAuditEvent };
