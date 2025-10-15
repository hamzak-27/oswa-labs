const mongoose = require('mongoose');

const labProgressSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  labId: {
    type: String,
    required: true,
    enum: ['xss-lab', 'jwt-attacks-lab'],
    index: true
  },
  status: {
    type: String,
    enum: ['not_started', 'in_progress', 'completed', 'paused'],
    default: 'not_started'
  },
  startedAt: {
    type: Date,
    default: Date.now
  },
  completedAt: {
    type: Date,
    default: null
  },
  lastActivity: {
    type: Date,
    default: Date.now
  },
  flagsSubmitted: [{
    flag: String,
    submittedAt: Date,
    points: Number,
    difficulty: String,
    type: String
  }],
  totalPoints: {
    type: Number,
    default: 0
  },
  timeSpent: {
    type: Number, // in minutes
    default: 0
  },
  hintsUsed: [{
    hintId: String,
    usedAt: Date,
    pointsPenalty: { type: Number, default: 0 }
  }],
  achievements: [{
    id: String,
    name: String,
    description: String,
    unlockedAt: Date,
    points: Number
  }],
  notes: {
    type: String,
    maxlength: 2000,
    default: ''
  },
  difficulty: {
    type: String,
    enum: ['easy', 'medium', 'hard'],
    default: 'medium'
  },
  metadata: {
    ipAddresses: [String],
    userAgents: [String],
    sessionIds: [String]
  }
}, {
  timestamps: true
});

// Compound indexes
labProgressSchema.index({ userId: 1, labId: 1 }, { unique: true });
labProgressSchema.index({ status: 1 });
labProgressSchema.index({ completedAt: -1 });
labProgressSchema.index({ totalPoints: -1 });

// Virtual for completion percentage
labProgressSchema.virtual('completionPercentage').get(function() {
  const totalFlags = {
    'xss-lab': 3,
    'jwt-attacks-lab': 5
  };
  
  const labTotalFlags = totalFlags[this.labId] || 1;
  return Math.round((this.flagsSubmitted.length / labTotalFlags) * 100);
});

// Method to add a flag submission
labProgressSchema.methods.addFlagSubmission = function(flagData) {
  this.flagsSubmitted.push({
    flag: flagData.flag,
    submittedAt: new Date(),
    points: flagData.points,
    difficulty: flagData.difficulty,
    type: flagData.type
  });
  
  this.totalPoints += flagData.points;
  this.lastActivity = new Date();
  
  // Check if lab is completed
  const totalFlags = {
    'xss-lab': 3,
    'jwt-attacks-lab': 5
  };
  
  if (this.flagsSubmitted.length >= totalFlags[this.labId]) {
    this.status = 'completed';
    this.completedAt = new Date();
  } else if (this.status === 'not_started') {
    this.status = 'in_progress';
  }
  
  return this.save();
};

// Method to add achievement
labProgressSchema.methods.addAchievement = function(achievement) {
  this.achievements.push({
    id: achievement.id,
    name: achievement.name,
    description: achievement.description,
    unlockedAt: new Date(),
    points: achievement.points || 0
  });
  
  if (achievement.points) {
    this.totalPoints += achievement.points;
  }
  
  return this.save();
};

// Static method to get user's overall progress
labProgressSchema.statics.getUserOverallProgress = function(userId) {
  return this.find({ userId })
    .sort({ lastActivity: -1 })
    .populate('userId', 'username email');
};

// Static method to get lab statistics
labProgressSchema.statics.getLabStats = function(labId) {
  return this.aggregate([
    { $match: { labId } },
    {
      $group: {
        _id: '$status',
        count: { $sum: 1 },
        avgPoints: { $avg: '$totalPoints' },
        avgCompletionTime: { $avg: '$timeSpent' }
      }
    }
  ]);
};

module.exports = mongoose.model('LabProgress', labProgressSchema);