const mongoose = require('mongoose');

const connectDB = async (serviceName) => {
  try {
    const uri = process.env.MONGO_URI || 'mongodb://mongodb:27017/cyberwall_xdr';
    const conn = await mongoose.connect(uri, {
      maxPoolSize: 10,
      socketTimeoutMS: 45000,
      serverSelectionTimeoutMS: 5000,
      heartbeatFrequencyMS: 10000,
    });
    console.log(`[${serviceName}] MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error(`[${serviceName}] MongoDB Connection Error: ${error.message}`);
    process.exit(1);
  }
};

module.exports = connectDB;
