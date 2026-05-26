const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const dotenv = require('dotenv');
const morgan = require('morgan');
const connectDB = require('../shared/dbConn');
const { connectRedis } = require('./config/redis');
const { connectKafka } = require('./config/kafka');

dotenv.config();

// Connect database and Redis publisher
connectDB('Threat Service');
connectRedis();
connectKafka();

const app = express();

app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json({ limit: '10mb' })); // Higher limit for batched traffic

if (process.env.NODE_ENV !== 'production') {
  app.use(morgan('dev'));
}

// Mount Routes
app.use('/api/alerts', require('./routes/alerts'));
app.use('/api/traffic', require('./routes/traffic'));
app.use('/api/rules', require('./routes/rules'));
app.use('/api/analytics', require('./routes/analytics'));

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'UP', service: 'Threat Service' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('[Threat Service Error]', err.stack);
  res.status(err.status || 500).json({
    success: false,
    error: err.message || 'Internal Server Error'
  });
});

const PORT = process.env.PORT || 5002;
app.listen(PORT, () => {
  console.log(`Threat Service running on port ${PORT}`);
});
