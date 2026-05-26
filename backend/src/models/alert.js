const mongoose = require('mongoose');

const AlertSchema = new mongoose.Schema({
  sourceIp: {
    type: String,
    required: true,
    index: true
  },
  destIp: {
    type: String,
    required: true
  },
  threatType: {
    type: String,
    required: true,
    enum: ['Port Scan', 'SYN Flood', 'DNS Anomaly', 'Brute Force', 'Suspicious Traffic Spike', 'Malicious IP Activity', 'Custom Rule Violation']
  },
  severity: {
    type: String,
    required: true,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'medium'
  },
  description: {
    type: String,
    required: true
  },
  status: {
    type: String,
    enum: ['active', 'acknowledged', 'resolved'],
    default: 'active',
    index: true
  },
  packetDetails: {
    type: Map,
    of: String
  },
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  },
  notes: {
    type: String,
    default: ''
  },
  acknowledgedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
});

// Compound indexes for common query patterns
AlertSchema.index({ status: 1, timestamp: -1 });    // getAlerts: filter by status, sort by timestamp
AlertSchema.index({ severity: 1, timestamp: -1 });  // getAlerts: filter by severity, sort by timestamp
AlertSchema.index({ sourceIp: 1, timestamp: -1 });  // getTopAttackers aggregation

module.exports = mongoose.model('Alert', AlertSchema);
