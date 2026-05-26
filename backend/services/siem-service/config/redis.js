const redis = require('redis');

const client = redis.createClient({
  url: process.env.REDIS_URL || 'redis://redis:6379'
});

client.on('error', (err) => console.error('[SIEM Service] Redis Client Error', err));

let isConnected = false;

const connectRedis = async () => {
  try {
    await client.connect();
    isConnected = true;
    console.log('[SIEM Service] Connected to Redis cache');
  } catch (error) {
    console.error('[SIEM Service] Failed to connect to Redis', error);
  }
};

module.exports = { client, connectRedis, isConnected: () => isConnected };
