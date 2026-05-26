const { consumer } = require('../config/kafka');
const { client: esClient } = require('../config/elasticsearch');
const { client: chClient } = require('../config/clickhouse');
const { normalizeEvent } = require('../pipeline/normalizer');
const { correlationEngine } = require('../pipeline/correlationEngine');

let trafficBatch = [];
const BATCH_SIZE = 100;
const FLUSH_INTERVAL_MS = 3000;

const flushClickHouseTraffic = async () => {
  if (trafficBatch.length === 0) return;
  const currentBatch = trafficBatch;
  trafficBatch = [];

  try {
    const values = currentBatch.map(item => ({
      timestamp: Date.parse(item.timestamp),
      sourceIp: item.sourceIp,
      destIp: item.destIp,
      protocol: item.protocol,
      destPort: item.destPort,
      packetSize: item.packetSize,
      flags: item.flags || '',
      dnsQuery: item.dnsQuery || ''
    }));

    await chClient.insert({
      table: 'default.traffic_logs',
      values,
      format: 'JSONEachRow'
    });
    console.log(`[SIEM Ingest] Flushed ${values.length} traffic rows to ClickHouse`);
  } catch (error) {
    console.error('[SIEM Ingest] ClickHouse traffic insertion failed', error.message);
  }
};

setInterval(flushClickHouseTraffic, FLUSH_INTERVAL_MS);

const startIngestionWorker = async () => {
  try {
    await consumer.subscribe({ topics: ['cyberwall-traffic', 'cyberwall-alerts'], fromBeginning: false });
    
    await consumer.run({
      eachMessage: async ({ topic, partition, message }) => {
        try {
          const payload = JSON.parse(message.value.toString());

          if (topic === 'cyberwall-traffic') {
            const entries = Array.isArray(payload) ? payload : [payload];
            
            for (const entry of entries) {
              const normalized = normalizeEvent('traffic', entry);
              
              esClient.index({
                index: 'cyberwall-events',
                body: normalized
              }).catch(e => {});

              trafficBatch.push(normalized);
              if (trafficBatch.length >= BATCH_SIZE) {
                await flushClickHouseTraffic();
              }
            }
          } else if (topic === 'cyberwall-alerts') {
            const normalized = normalizeEvent('alert', payload);

            esClient.index({
              index: 'cyberwall-events',
              body: normalized
            }).catch(e => {});

            const chAlert = {
              timestamp: Date.parse(normalized.timestamp),
              sourceIp: normalized.sourceIp,
              destIp: normalized.destIp,
              threatType: normalized.threatType,
              severity: normalized.severity,
              description: normalized.description,
              mitreId: normalized.mitreId,
              mitreName: normalized.mitreName,
              tags: normalized.tags
            };

            await chClient.insert({
              table: 'default.alert_logs',
              values: [chAlert],
              format: 'JSONEachRow'
            }).catch(e => console.error('[SIEM Ingest] ClickHouse alert insertion failed', e.message));

            await correlationEngine.processAlert(normalized);
          }
        } catch (msgErr) {
          console.error('[SIEM Ingest] Error handling single message', msgErr.message);
        }
      }
    });
    
    console.log('[SIEM Ingest] Ingestion consumer worker running and listening on Kafka topics');
  } catch (error) {
    console.error('[SIEM Ingest] Ingestion worker crashed on startup', error.message);
  }
};

module.exports = { startIngestionWorker };
