const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 30
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  role: {
    type: String,
    enum: ['admin', 'user', 'service', 'guest'],
    default: 'user'
  },
  permissions: [{
    type: String,
    enum: ['read', 'write', 'delete', 'admin', 'jwt_debug', 'api_access', 'service_to_service', 'process_payments', 'read_transactions', 'manage_users', 'read_profiles', 'admin_access', 'system_control']
  }],
  is_active: {
    type: Boolean,
    default: true
  },
  secret_data: {
    type: String,
    default: null
  },
  profile: {
    firstName: {
      type: String,
      trim: true,
      maxlength: 50
    },
    lastName: {
      type: String,
      trim: true,
      maxlength: 50
    },
    bio: {
      type: String,
      maxlength: 500
    },
    avatar: {
      type: String,
      default: '/uploads/default-avatar.png'
    },
    clearance_level: {
      type: String,
      enum: ['PUBLIC', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'],
      default: 'PUBLIC'
    }
  },
  api_key: {
    type: String,
    default: null
  },
  created_at: {
    type: Date,
    default: Date.now
  },
  last_login: {
    type: Date,
    default: Date.now
  },
  jwt_version: {
    type: Number,
    default: 1
  },
  disabled_reason: {
    type: String,
    default: null
  },
  login_attempts: {
    type: Number,
    default: 0
  },
  lock_until: {
    type: Date,
    default: null
  }
}, {
  timestamps: true,
  toJSON: { 
    virtuals: true,
    transform: function(doc, ret) {
      delete ret.password;
      return ret;
    }
  },
  toObject: { virtuals: true }
});

// Virtual for full name
userSchema.virtual('fullName').get(function() {
  if (this.profile.firstName && this.profile.lastName) {
    return `${this.profile.firstName} ${this.profile.lastName}`;
  }
  return this.username;
});

// Virtual for account lock status
userSchema.virtual('isLocked').get(function() {
  return !!(this.lock_until && this.lock_until > Date.now());
});

// Indexes
userSchema.index({ username: 1 });
userSchema.index({ email: 1 });
userSchema.index({ role: 1 });
userSchema.index({ is_active: 1 });
userSchema.index({ api_key: 1 });

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare password
userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Method to increment login attempts
userSchema.methods.incLoginAttempts = function() {
  if (this.lock_until && this.lock_until < Date.now()) {
    return this.updateOne({
      $unset: { lock_until: 1 },
      $set: { login_attempts: 1 }
    });
  }
  
  const updates = { $inc: { login_attempts: 1 } };
  
  if (this.login_attempts + 1 >= 5 && !this.isLocked) {
    updates.$set = { lock_until: Date.now() + 30 * 60 * 1000 }; // 30 minutes
  }
  
  return this.updateOne(updates);
};

// Static method to get authenticated user
userSchema.statics.getAuthenticated = function(identifier, password) {
  return this.findOne({
    $or: [
      { username: identifier },
      { email: identifier }
    ]
  }).then(user => {
    if (!user) {
      return Promise.reject(new Error('User not found'));
    }
    
    if (user.isLocked) {
      return Promise.reject(new Error('Account temporarily locked'));
    }
    
    return user.comparePassword(password).then(isMatch => {
      if (isMatch) {
        if (user.login_attempts > 0) {
          return user.updateOne({
            $unset: { login_attempts: 1, lock_until: 1 },
            $set: { last_login: Date.now() }
          }).then(() => user);
        }
        
        user.last_login = Date.now();
        return user.save();
      } else {
        user.incLoginAttempts();
        return Promise.reject(new Error('Invalid password'));
      }
    });
  });
};

module.exports = mongoose.model('User', userSchema);