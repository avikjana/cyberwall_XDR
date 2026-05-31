const mongoose = require('mongoose');

const RuleSchema = new mongoose.Schema({
  ip: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  type: {
    type: String,
    enum: ['IP', 'DOMAIN'],
    default: 'IP'
  },
  reason: {
    type: String,
    required: true
  },
  action: {
    type: String,
    enum: ['BLOCK', 'ALLOW'],
    default: 'BLOCK'
  },
  addedBy: {
    type: String,
    default: 'SYSTEM'
  },
  status: {
    type: String,
    enum: ['active', 'removed'],
    default: 'active'
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  expiresAt: {
    type: Date
  },
  resolvedDomain: {
    type: String,
    default: 'N/A'
  },
  resolvedIp: {
    type: String,
    default: 'N/A'
  }
});

module.exports = mongoose.model('Rule', RuleSchema);
