const { Kafka } = require('kafkajs');

const brokers = (process.env.KAFKA_BROKERS || 'localhost:9092').split(',');

const kafka = new Kafka({
  clientId: 'cyberwall-siem-service',
  brokers: brokers,
  connectionTimeout: 3000,
  requestTimeout: 6000,
  retry: {
    retries: 3
  }
});

const consumer = kafka.consumer({ groupId: 'cyberwall-siem-group' });
let isConnected = false;

const connectKafkaConsumer = async () => {
  try {
    await consumer.connect();
    isConnected = true;
    console.log('[SIEM Service] Connected to Kafka Consumer');
  } catch (error) {
    console.error('[SIEM Service] Failed to connect to Kafka Consumer', error.message);
  }
};

module.exports = { kafka, consumer, connectKafkaConsumer, isConnected: () => isConnected };
