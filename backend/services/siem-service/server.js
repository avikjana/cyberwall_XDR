const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const dotenv = require('dotenv');
const morgan = require('morgan');

const { connectRedis } = require('./config/redis');
const { connectKafkaConsumer } = require('./config/kafka');
const { connectElasticsearch } = require('./config/elasticsearch');
const { connectClickHouse } = require('./config/clickhouse');
const { startIngestionWorker } = require('./workers/ingestWorker');

dotenv.config();

const app = express();

app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json());

if (process.env.NODE_ENV !== 'production') {
  app.use(morgan('dev'));
}

// Mount Routes
app.use('/api/siem', require('./routes/siem'));

// Service Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'UP', 
    service: 'SIEM & Analytics Service' 
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('[SIEM Service Error]', err.stack || err.message);
  res.status(err.status || 500).json({
    success: false,
    error: err.message || 'Internal Server Error'
  });
});

const PORT = process.env.PORT || 5005;

const startServer = async () => {
  console.log('============================================================');
  console.log('  CyberWall XDR – SIEM & Big Data Analytics Service v1.0');
  console.log('============================================================');

  // Boot dependencies in parallel
  await Promise.all([
    connectRedis(),
    connectElasticsearch(),
    connectClickHouse()
  ]);

  // Connect Kafka and start consumer loop
  await connectKafkaConsumer();
  startIngestionWorker();

  app.listen(PORT, () => {
    console.log(`SIEM Service running on port ${PORT}`);
  });
};

startServer();
