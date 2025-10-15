const mongoose = require('mongoose');

const commentSchema = new mongoose.Schema({
  postId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Post',
    required: true
  },
  content: {
    type: String,
    required: true,
    maxlength: 1000
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
  parentComment: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Comment',
    default: null
  },
  likes: {
    type: Number,
    default: 0
  },
  likedBy: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  reported: {
    type: Boolean,
    default: false
  },
  reportedBy: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    reason: String,
    reportedAt: { type: Date, default: Date.now }
  }],
  isDeleted: {
    type: Boolean,
    default: false
  },
  deletedAt: Date,
  deletedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  editHistory: [{
    content: String,
    editedAt: { type: Date, default: Date.now },
    editReason: String
  }],
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

// Virtual for replies count
commentSchema.virtual('repliesCount', {
  ref: 'Comment',
  localField: '_id',
  foreignField: 'parentComment',
  count: true
});

// Indexes
commentSchema.index({ postId: 1, createdAt: 1 });
commentSchema.index({ author: 1 });
commentSchema.index({ parentComment: 1 });
commentSchema.index({ reported: 1 });

// Static method to find comments for a post
commentSchema.statics.findByPost = function(postId, options = {}) {
  const { page = 1, limit = 20, sort = { createdAt: 1 } } = options;
  
  return this.find({ 
    postId: postId, 
    parentComment: null,
    isDeleted: false 
  })
    .populate('author', 'username profile.firstName profile.lastName profile.avatar')
    .sort(sort)
    .limit(limit)
    .skip((page - 1) * limit);
};

// Static method to find replies to a comment
commentSchema.statics.findReplies = function(commentId) {
  return this.find({ 
    parentComment: commentId,
    isDeleted: false 
  })
    .populate('author', 'username profile.firstName profile.lastName profile.avatar')
    .sort({ createdAt: 1 });
};

module.exports = mongoose.model('Comment', commentSchema);