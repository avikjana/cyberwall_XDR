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
    required: true
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

module.exports = mongoose.model('Traffic', TrafficSchema);
