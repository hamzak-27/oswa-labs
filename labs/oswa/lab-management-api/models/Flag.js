const mongoose = require('mongoose');

const flagSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  username: {
    type: String,
    required: true
  },
  flag: {
    type: String,
    required: true,
    match: /^FLAG\{[A-Z0-9_]+\}$/
  },
  labId: {
    type: String,
    required: true,
    enum: ['xss-lab', 'jwt-attacks-lab'],
    index: true
  },
  category: {
    type: String,
    required: true,
    enum: ['xss', 'jwt', 'sqli', 'csrf', 'xxe', 'ssrf', 'file-upload', 'auth']
  },
  difficulty: {
    type: String,
    required: true,
    enum: ['easy', 'medium', 'hard']
  },
  points: {
    type: Number,
    required: true,
    min: 0,
    max: 1000
  },
  type: {
    type: String,
    required: true
  },
  notes: {
    type: String,
    maxlength: 500,
    default: ''
  },
  submittedAt: {
    type: Date,
    default: Date.now,
    index: true
  },
  ipAddress: {
    type: String,
    required: true
  },
  userAgent: {
    type: String,
    default: ''
  },
  verified: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true
});

// Compound indexes for better query performance
flagSchema.index({ userId: 1, labId: 1 });
flagSchema.index({ userId: 1, flag: 1, labId: 1 }, { unique: true });
flagSchema.index({ submittedAt: -1 });
flagSchema.index({ points: -1 });

// Static method to get user's progress for a specific lab
flagSchema.statics.getUserLabProgress = function(userId, labId) {
  return this.find({ userId, labId })
    .sort({ submittedAt: 1 })
    .select('flag points difficulty type submittedAt');
};

// Static method to get leaderboard
flagSchema.statics.getLeaderboard = function(labId = null, limit = 50) {
  const matchStage = labId ? { labId } : {};
  
  return this.aggregate([
    { $match: matchStage },
    {
      $group: {
        _id: '$userId',
        username: { $first: '$username' },
        totalPoints: { $sum: '$points' },
        flagsCount: { $sum: 1 },
        lastSubmission: { $max: '$submittedAt' }
      }
    },
    { $sort: { totalPoints: -1, lastSubmission: -1 } },
    { $limit: limit }
  ]);
};

module.exports = mongoose.model('Flag', flagSchema);