const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  event_type: {
    type: String,
    required: true,
    enum: ['login_attempt', 'token_validation', 'jwt_signing', 'admin_access', 'api_access', 'vulnerability_exploit'],
    index: true
  },
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  username: {
    type: String,
    default: 'anonymous'
  },
  success: {
    type: Boolean,
    required: true,
    index: true
  },
  jwt_algorithm: {
    type: String,
    enum: ['HS256', 'HS512', 'RS256', 'none', 'unknown'],
    default: 'unknown'
  },
  ip_address: {
    type: String,
    required: true
  },
  user_agent: {
    type: String,
    default: ''
  },
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  },
  details: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  severity: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'low'
  },
  vulnerability_exploited: {
    type: String,
    enum: ['none_algorithm', 'weak_secret', 'algorithm_confusion', 'kid_injection', 'privilege_escalation'],
    default: null
  }
}, {
  timestamps: true
});

// Indexes for better performance
auditLogSchema.index({ timestamp: -1 });
auditLogSchema.index({ event_type: 1, timestamp: -1 });
auditLogSchema.index({ user_id: 1, timestamp: -1 });
auditLogSchema.index({ success: 1, timestamp: -1 });

// Static method to log JWT vulnerabilities
auditLogSchema.statics.logVulnerability = function(vulnerability, details = {}) {
  return this.create({
    event_type: 'vulnerability_exploit',
    success: true,
    vulnerability_exploited: vulnerability,
    severity: this.getSeverityByVulnerability(vulnerability),
    ip_address: details.ip_address || '127.0.0.1',
    user_agent: details.user_agent || 'Unknown',
    details: details
  });
};

// Static method to get severity by vulnerability type
auditLogSchema.statics.getSeverityByVulnerability = function(vulnerability) {
  const severityMap = {
    'none_algorithm': 'high',
    'weak_secret': 'medium',
    'algorithm_confusion': 'critical',
    'kid_injection': 'critical',
    'privilege_escalation': 'critical'
  };
  
  return severityMap[vulnerability] || 'low';
};

module.exports = mongoose.model('AuditLog', auditLogSchema);