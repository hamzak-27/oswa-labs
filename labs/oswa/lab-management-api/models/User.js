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
    enum: ['student', 'instructor', 'admin'],
    default: 'student'
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
    institution: {
      type: String,
      trim: true,
      maxlength: 100
    },
    experience: {
      type: String,
      enum: ['beginner', 'intermediate', 'advanced', 'expert'],
      default: 'beginner'
    }
  },
  stats: {
    totalPoints: {
      type: Number,
      default: 0
    },
    flagsSubmitted: {
      type: Number,
      default: 0
    },
    labsCompleted: {
      type: Number,
      default: 0
    },
    totalTimeSpent: {
      type: Number, // in minutes
      default: 0
    },
    currentStreak: {
      type: Number,
      default: 0
    },
    longestStreak: {
      type: Number,
      default: 0
    },
    achievementsUnlocked: {
      type: Number,
      default: 0
    }
  },
  settings: {
    emailNotifications: {
      type: Boolean,
      default: true
    },
    darkMode: {
      type: Boolean,
      default: false
    },
    publicProfile: {
      type: Boolean,
      default: true
    },
    showOnLeaderboard: {
      type: Boolean,
      default: true
    },
    difficulty: {
      type: String,
      enum: ['easy', 'medium', 'hard'],
      default: 'medium'
    }
  },
  lastLoginAt: {
    type: Date,
    default: Date.now
  },
  lastActiveAt: {
    type: Date,
    default: Date.now
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  verificationToken: {
    type: String,
    default: null
  },
  passwordResetToken: {
    type: String,
    default: null
  },
  passwordResetExpires: {
    type: Date,
    default: null
  },
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: {
    type: Date,
    default: null
  },
  isActive: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true,
  toJSON: {
    virtuals: true,
    transform: function(doc, ret) {
      delete ret.password;
      delete ret.verificationToken;
      delete ret.passwordResetToken;
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
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Virtual for user rank based on points
userSchema.virtual('rank').get(function() {
  // This would typically be calculated via aggregation
  // For now, return a placeholder
  return 0;
});

// Indexes
userSchema.index({ username: 1 });
userSchema.index({ email: 1 });
userSchema.index({ 'stats.totalPoints': -1 });
userSchema.index({ lastActiveAt: -1 });
userSchema.index({ createdAt: -1 });

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
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { lockUntil: 1 },
      $set: { loginAttempts: 1 }
    });
  }
  
  const updates = { $inc: { loginAttempts: 1 } };
  
  if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + 2 * 60 * 60 * 1000 }; // 2 hours
  }
  
  return this.updateOne(updates);
};

// Method to update user stats
userSchema.methods.updateStats = function(statsUpdate) {
  Object.keys(statsUpdate).forEach(key => {
    if (this.stats[key] !== undefined) {
      this.stats[key] += statsUpdate[key];
    }
  });
  
  return this.save();
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
    
    if (!user.isActive) {
      return Promise.reject(new Error('Account deactivated'));
    }
    
    if (user.isLocked) {
      return Promise.reject(new Error('Account temporarily locked'));
    }
    
    return user.comparePassword(password).then(isMatch => {
      if (isMatch) {
        if (user.loginAttempts > 0) {
          return user.updateOne({
            $unset: { loginAttempts: 1, lockUntil: 1 },
            $set: { lastLoginAt: Date.now(), lastActiveAt: Date.now() }
          }).then(() => user);
        }
        
        user.lastLoginAt = Date.now();
        user.lastActiveAt = Date.now();
        return user.save();
      } else {
        user.incLoginAttempts();
        return Promise.reject(new Error('Invalid password'));
      }
    });
  });
};

// Static method to get leaderboard
userSchema.statics.getLeaderboard = function(limit = 50, timeframe = 'all') {
  return this.find({ isActive: true, 'settings.showOnLeaderboard': true })
    .sort({ 'stats.totalPoints': -1, 'stats.flagsSubmitted': -1, lastActiveAt: -1 })
    .limit(limit)
    .select('username profile.firstName profile.lastName stats.totalPoints stats.flagsSubmitted stats.labsCompleted')
    .lean();
};

module.exports = mongoose.model('User', userSchema);