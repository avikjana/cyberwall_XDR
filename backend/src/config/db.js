const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/cyberwall_xdr', {
      maxPoolSize: 10,              // Allow up to 10 concurrent DB connections
      socketTimeoutMS: 45000,       // Close sockets after 45s of inactivity
      serverSelectionTimeoutMS: 5000, // Fail fast on connection issues
      heartbeatFrequencyMS: 10000,  // Monitor connection health every 10s
    });
    console.log(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error(`MongoDB Connection Error: ${error.message}`);
    process.exit(1);
  }
};

module.exports = connectDB;
