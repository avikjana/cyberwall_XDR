const redis = require('redis');

const client = redis.createClient({
  url: process.env.REDIS_URL || 'redis://redis:6379'
});

client.on('error', (err) => console.error('[Threat Service] Redis Client Error', err));

let isConnected = false;

const connectRedis = async () => {
  try {
    await client.connect();
    isConnected = true;
    console.log('[Threat Service] Connected to Redis publisher');
  } catch (error) {
    console.error('[Threat Service] Failed to connect to Redis', error);
  }
};

const publishEvent = (channel, data) => {
  if (!isConnected) {
    console.warn('[Threat Service] Redis not connected, skipping publish');
    return;
  }
  client.publish(channel, JSON.stringify(data));
};

module.exports = { connectRedis, publishEvent };
