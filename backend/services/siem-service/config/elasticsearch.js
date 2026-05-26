const { Client } = require('@elastic/elasticsearch');

const esNode = process.env.ELASTICSEARCH_NODE || 'http://localhost:9200';

const client = new Client({
  node: esNode,
  requestTimeout: 5000,
  maxRetries: 3
});

let isConnected = false;

const connectElasticsearch = async () => {
  try {
    await client.ping();
    isConnected = true;
    console.log('[SIEM Service] Connected to Elasticsearch');

    const indexExists = await client.indices.exists({ index: 'cyberwall-events' });
    if (!indexExists) {
      await client.indices.create({
        index: 'cyberwall-events',
        body: {
          mappings: {
            properties: {
              timestamp: { type: 'date' },
              eventType: { type: 'keyword' },
              sourceIp: { type: 'ip' },
              destIp: { type: 'ip' },
              protocol: { type: 'keyword' },
              destPort: { type: 'integer' },
              packetSize: { type: 'integer' },
              severity: { type: 'keyword' },
              threatType: { type: 'keyword' },
              description: { type: 'text' },
              mitreId: { type: 'keyword' },
              mitreName: { type: 'keyword' },
              tags: { type: 'keyword' }
            }
          }
        }
      });
      console.log("[SIEM Service] Created index 'cyberwall-events' with custom schema");
    }
  } catch (error) {
    console.error('[SIEM Service] Failed to connect to Elasticsearch', error.message);
  }
};

module.exports = { client, connectElasticsearch, isConnected: () => isConnected };
