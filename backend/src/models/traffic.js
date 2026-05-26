const mongoose = require('mongoose');

const TrafficSchema = new mongoose.Schema({
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  },
  protocol: {
    type: String,
    enum: ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'OTHER'],
    required: true,
    index: true  // Supports protocol-filtered queries and aggregation grouping
  },
  sourceIp: {
    type: String,
    required: true
  },
  sourcePort: {
    type: Number
  },
  destIp: {
    type: String,
    required: true
  },
  destPort: {
    type: Number
  },
  packetSize: {
    type: Number,
    required: true
  },
  flags: {
    type: String,
    default: ''
  }
});

// Compound index for the most common query: latest traffic filtered by protocol
TrafficSchema.index({ timestamp: -1, protocol: 1 });

// TTL index: auto-expire traffic documents older than 24 hours
// Prevents unbounded collection growth (this is the highest-volume collection)
TrafficSchema.index({ timestamp: 1 }, { expireAfterSeconds: 86400 });

module.exports = mongoose.model('Traffic', TrafficSchema);
