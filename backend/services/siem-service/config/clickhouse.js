const { createClient } = require('@clickhouse/client');

const host = process.env.CLICKHOUSE_HOST || 'http://localhost:8123';

const client = createClient({
  host: host,
  username: 'default',
  password: '',
  database: 'default',
  clickhouse_settings: {
    connect_timeout: 5000
  }
});

let isConnected = false;

const connectClickHouse = async () => {
  try {
    const rs = await client.ping();
    if (rs) {
      isConnected = true;
      console.log('[SIEM Service] Connected to ClickHouse');

      await client.query({
        query: `
          CREATE TABLE IF NOT EXISTS default.traffic_logs (
            timestamp DateTime64(3, 'UTC'),
            sourceIp String,
            destIp String,
            protocol String,
            destPort UInt16,
            packetSize UInt32,
            flags String,
            dnsQuery String
          ) ENGINE = MergeTree()
          ORDER BY (timestamp, protocol, sourceIp)
        `
      });

      await client.query({
        query: `
          CREATE TABLE IF NOT EXISTS default.alert_logs (
            timestamp DateTime64(3, 'UTC'),
            sourceIp String,
            destIp String,
            threatType String,
            severity String,
            description String,
            mitreId String,
            mitreName String,
            tags Array(String)
          ) ENGINE = MergeTree()
          ORDER BY (timestamp, severity, threatType)
        `
      });

      console.log('[SIEM Service] ClickHouse database tables initialized');
    }
  } catch (error) {
    console.error('[SIEM Service] Failed to connect to ClickHouse', error.message);
  }
};

module.exports = { client, connectClickHouse, isConnected: () => isConnected };
