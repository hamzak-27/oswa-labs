const mongoose = require('mongoose');

const serviceSchema = new mongoose.Schema({
  service_name: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  service_id: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  api_key: {
    type: String,
    required: true,
    unique: true
  },
  jwt_algorithm: {
    type: String,
    enum: ['HS256', 'HS512', 'RS256', 'none'],
    default: 'HS256'
  },
  secret: {
    type: String,
    default: null // null for RSA algorithms
  },
  permissions: [{
    type: String
  }],
  is_active: {
    type: Boolean,
    default: true
  },
  created_at: {
    type: Date,
    default: Date.now
  },
  last_used: {
    type: Date,
    default: Date.now
  },
  request_count: {
    type: Number,
    default: 0
  },
  rate_limit: {
    type: Number,
    default: 1000 // requests per hour
  },
  description: {
    type: String,
    maxlength: 500
  },
  environment: {
    type: String,
    enum: ['development', 'staging', 'production'],
    default: 'development'
  }
}, {
  timestamps: true
});

// Indexes
serviceSchema.index({ service_id: 1 });
serviceSchema.index({ api_key: 1 });
serviceSchema.index({ is_active: 1 });
serviceSchema.index({ jwt_algorithm: 1 });

// Method to update usage stats
serviceSchema.methods.updateUsage = function() {
  this.last_used = new Date();
  this.request_count += 1;
  return this.save();
};

// Static method to find active services
serviceSchema.statics.findActive = function() {
  return this.find({ is_active: true });
};

module.exports = mongoose.model('Service', serviceSchema);