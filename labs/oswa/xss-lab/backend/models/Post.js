const mongoose = require('mongoose');

const postSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true,
    maxlength: 200
  },
  content: {
    type: String,
    required: true
  },
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  authorUsername: {
    type: String,
    required: true
  },
  tags: [{
    type: String,
    trim: true,
    lowercase: true
  }],
  likes: {
    type: Number,
    default: 0
  },
  likedBy: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  views: {
    type: Number,
    default: 0
  },
  reported: {
    type: Boolean,
    default: false
  },
  reportedBy: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    reason: String,
    reportedAt: { type: Date, default: Date.now }
  }],
  isSticky: {
    type: Boolean,
    default: false
  },
  isLocked: {
    type: Boolean,
    default: false
  },
  visibility: {
    type: String,
    enum: ['public', 'private', 'friends'],
    default: 'public'
  },
  allowComments: {
    type: Boolean,
    default: true
  },
  metadata: {
    ipAddress: String,
    userAgent: String,
    source: String
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual for comment count
postSchema.virtual('commentCount', {
  ref: 'Comment',
  localField: '_id',
  foreignField: 'postId',
  count: true
});

// Indexes for better performance
postSchema.index({ title: 'text', content: 'text' });
postSchema.index({ author: 1, createdAt: -1 });
postSchema.index({ tags: 1 });
postSchema.index({ createdAt: -1 });
postSchema.index({ reported: 1 });

// Middleware to increment views
postSchema.methods.incrementViews = function() {
  this.views = (this.views || 0) + 1;
  return this.save();
};

// Static method to find popular posts
postSchema.statics.findPopular = function(limit = 10) {
  return this.find({ visibility: 'public' })
    .sort({ likes: -1, views: -1, createdAt: -1 })
    .limit(limit)
    .populate('author', 'username profile.firstName profile.lastName profile.avatar');
};

// Static method to find recent posts
postSchema.statics.findRecent = function(limit = 20) {
  return this.find({ visibility: 'public' })
    .sort({ createdAt: -1 })
    .limit(limit)
    .populate('author', 'username profile.firstName profile.lastName profile.avatar');
};

module.exports = mongoose.model('Post', postSchema);