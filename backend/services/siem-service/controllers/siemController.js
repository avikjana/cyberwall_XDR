const { client: esClient, isConnected: esConnected } = require('../config/elasticsearch');
const { client: chClient, isConnected: chConnected } = require('../config/clickhouse');
const { isConnected: kafkaConnected } = require('../config/kafka');

// Elasticsearch Search Controller
exports.searchEvents = async (req, res) => {
  try {
    if (!esConnected()) {
      return res.status(503).json({ success: false, error: 'Elasticsearch search engine offline' });
    }

    const { q, eventType, severity, sourceIp, page = 1, limit = 50 } = req.query;
    const parsedPage = Number(page);
    const parsedLimit = Number(limit);
    const from = (parsedPage - 1) * parsedLimit;

    // Build Elasticsearch query
    const must = [];
    if (eventType) must.push({ term: { eventType } });
    if (severity) must.push({ term: { severity } });
    if (sourceIp) must.push({ term: { sourceIp } });

    if (q) {
      must.push({
        multi_match: {
          query: q,
          fields: ['description', 'threatType', 'mitreName', 'protocol', 'tags']
        }
      });
    }

    const query = must.length > 0 ? { bool: { must } } : { match_all: {} };

    const searchResponse = await esClient.search({
      index: 'cyberwall-events',
      body: {
        query,
        sort: [{ timestamp: { order: 'desc' } }],
        from,
        size: parsedLimit
      }
    });

    const hits = searchResponse.hits.hits.map(hit => ({
      id: hit._id,
      ...hit._source
    }));

    res.status(200).json({
      success: true,
      total: typeof searchResponse.hits.total === 'object' ? searchResponse.hits.total.value : searchResponse.hits.total,
      count: hits.length,
      currentPage: parsedPage,
      totalPages: Math.ceil((typeof searchResponse.hits.total === 'object' ? searchResponse.hits.total.value : searchResponse.hits.total) / parsedLimit),
      data: hits
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

// ClickHouse Analytics Controllers
exports.getOverviewStats = async (req, res) => {
  try {
    if (!chConnected()) {
      return res.status(503).json({ success: false, error: 'ClickHouse analytics database offline' });
    }

    const trafficQuery = await chClient.query({
      query: 'SELECT count() as totalTraffic FROM default.traffic_logs',
      format: 'JSONEachRow'
    });
    const trafficData = await trafficQuery.json();

    const alertsQuery = await chClient.query({
      query: "SELECT count() as activeThreats FROM default.alert_logs WHERE threatType != 'normal'",
      format: 'JSONEachRow'
    });
    const alertsData = await alertsQuery.json();

    const rulesQuery = await chClient.query({
      query: "SELECT count() as totalCorrelated FROM default.alert_logs WHERE has(tags, 'correlated')",
      format: 'JSONEachRow'
    });
    const rulesData = await rulesQuery.json();

    res.status(200).json({
      success: true,
      data: {
        totalTraffic: Number(trafficData[0]?.totalTraffic || 0),
        activeThreats: Number(alertsData[0]?.activeThreats || 0),
        totalBlocked: Number(rulesData[0]?.totalCorrelated || 0),
        systemStatus: {
          cpu: Math.floor(Math.random() * 15) + 3,
          ram: Math.floor(Math.random() * 10) + 30,
          disk: 24
        }
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

exports.getProtocolDistribution = async (req, res) => {
  try {
    if (!chConnected()) {
      return res.status(503).json({ success: false, error: 'ClickHouse analytics database offline' });
    }

    const rs = await chClient.query({
      query: `
        SELECT 
          protocol, 
          count() as count, 
          sum(packetSize) as bytes 
        FROM default.traffic_logs 
        GROUP BY protocol
      `,
      format: 'JSONEachRow'
    });
    const distribution = await rs.json();

    // Map ClickHouse BigInt/String representations to JS types
    const formatted = distribution.map(item => ({
      protocol: item.protocol,
      count: Number(item.count),
      bytes: Number(item.bytes)
    }));

    res.status(200).json({ success: true, data: formatted });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

exports.getTopAttackers = async (req, res) => {
  try {
    if (!chConnected()) {
      return res.status(503).json({ success: false, error: 'ClickHouse analytics database offline' });
    }

    const rs = await chClient.query({
      query: `
        SELECT 
          sourceIp as ip, 
          count() as count,
          groupArray(threatType) as threats
        FROM default.alert_logs
        WHERE sourceIp != '0.0.0.0' AND sourceIp != '127.0.0.1'
        GROUP BY sourceIp
        ORDER BY count DESC
        LIMIT 10
      `,
      format: 'JSONEachRow'
    });
    const attackers = await rs.json();

    const formatted = attackers.map(item => ({
      ip: item.ip,
      count: Number(item.count),
      threats: [...new Set(item.threats)].slice(0, 3) // Unique slice
    }));

    res.status(200).json({ success: true, data: formatted });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

exports.getThreatSeverityDistribution = async (req, res) => {
  try {
    if (!chConnected()) {
      return res.status(503).json({ success: false, error: 'ClickHouse analytics database offline' });
    }

    const rs = await chClient.query({
      query: `
        SELECT 
          severity, 
          count() as count
        FROM default.alert_logs
        GROUP BY severity
      `,
      format: 'JSONEachRow'
    });
    const distribution = await rs.json();

    const formatted = distribution.map(item => ({
      severity: item.severity,
      count: Number(item.count)
    }));

    res.status(200).json({ success: true, data: formatted });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

exports.getTrafficTimeline = async (req, res) => {
  try {
    if (!chConnected()) {
      return res.status(503).json({ success: false, error: 'ClickHouse analytics database offline' });
    }

    // Bin by minute for the last hour
    const rs = await chClient.query({
      query: `
        SELECT 
          formatDateTime(toStartOfMinute(timestamp), '%H:%i') as timeSlot,
          count() as packets,
          sum(packetSize) as bytes
        FROM default.traffic_logs
        WHERE timestamp >= now() - INTERVAL 1 HOUR
        GROUP BY timeSlot
        ORDER BY timeSlot ASC
      `,
      format: 'JSONEachRow'
    });
    const timeline = await rs.json();

    const formatted = timeline.map(item => ({
      time: item.timeSlot,
      packets: Number(item.packets),
      bytes: Number(item.bytes)
    }));

    res.status(200).json({ success: true, data: formatted });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

exports.getDetectionTrends = async (req, res) => {
  try {
    if (!chConnected()) {
      return res.status(503).json({ success: false, error: 'ClickHouse analytics database offline' });
    }

    const rs = await chClient.query({
      query: `
        SELECT 
          threatType,
          count() as count
        FROM default.alert_logs
        GROUP BY threatType
        ORDER BY count DESC
      `,
      format: 'JSONEachRow'
    });
    const trends = await rs.json();

    const formatted = trends.map(item => ({
      threatType: item.threatType,
      count: Number(item.count)
    }));

    res.status(200).json({ success: true, data: formatted });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};
