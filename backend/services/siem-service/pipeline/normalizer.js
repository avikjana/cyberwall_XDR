const normalizeEvent = (type, data) => {
  const now = new Date().toISOString();
  
  if (type === 'traffic') {
    return {
      timestamp: data.timestamp || now,
      eventType: 'traffic',
      sourceIp: data.sourceIp || '0.0.0.0',
      destIp: data.destIp || '0.0.0.0',
      protocol: data.protocol || 'UNKNOWN',
      destPort: Number(data.destPort) || 0,
      packetSize: Number(data.packetSize) || 0,
      flags: data.flags || '',
      dnsQuery: data.dnsQuery || '',
      severity: 'info',
      threatType: 'normal',
      description: `Traffic log: ${data.protocol} packet from ${data.sourceIp} to ${data.destIp}`,
      mitreId: '',
      mitreName: '',
      tags: ['network', 'raw-traffic']
    };
  } else if (type === 'alert') {
    let tagsList = [];
    if (Array.isArray(data.tags)) {
      tagsList = data.tags;
    } else if (typeof data.tags === 'string') {
      tagsList = data.tags.split(',').map(t => t.trim()).filter(Boolean);
    }

    return {
      timestamp: data.timestamp || now,
      eventType: 'alert',
      sourceIp: data.sourceIp || '0.0.0.0',
      destIp: data.destIp || '0.0.0.0',
      protocol: data.protocol || 'UNKNOWN',
      destPort: Number(data.destPort) || 0,
      packetSize: Number(data.packetSize) || 0,
      severity: data.severity || 'medium',
      threatType: data.threatType || 'unknown',
      description: data.description || 'Security alert triggered',
      mitreId: data.mitreId || data.mitre_id || '',
      mitreName: data.mitreName || data.mitre_name || '',
      tags: ['security', 'alert', ...tagsList]
    };
  }
  
  return {
    timestamp: now,
    eventType: 'unknown',
    description: JSON.stringify(data)
  };
};

module.exports = { normalizeEvent };
