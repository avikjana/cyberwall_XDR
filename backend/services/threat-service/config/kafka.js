const { Kafka } = require('kafkajs');

const brokers = (process.env.KAFKA_BROKERS || 'localhost:9092').split(',');

const kafka = new Kafka({
  clientId: 'cyberwall-threat-service',
  brokers: brokers,
  connectionTimeout: 3000,
  requestTimeout: 6000,
  retry: {
    retries: 2
  }
});

const producer = kafka.producer();
let isConnected = false;

const connectKafka = async () => {
  if (!process.env.KAFKA_BROKERS) {
    console.log('[Threat Service] Kafka not configured, running without SIEM pipeline');
    return;
  }
  try {
    await producer.connect();
    isConnected = true;
    console.log('[Threat Service] Connected to Kafka producer');
  } catch (error) {
    console.error('[Threat Service] Failed to connect to Kafka producer', error.message);
  }
};

const publishToKafka = async (topic, messages) => {
  if (!isConnected) {
    return; // Silent fail-open fallback
  }
  try {
    await producer.send({
      topic,
      messages: Array.isArray(messages) 
        ? messages.map(m => ({ value: JSON.stringify(m) }))
        : [{ value: JSON.stringify(messages) }]
    });
  } catch (error) {
    console.error(`[Threat Service] Failed to publish message to topic ${topic}`, error.message);
  }
};

module.exports = { connectKafka, publishToKafka };
