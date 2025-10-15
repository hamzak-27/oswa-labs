const express = require('express');
const router = express.Router();
const Post = require('../models/Post');
const Comment = require('../models/Comment');

// Simple admin middleware
const adminMiddleware = (req, res, next) => {
  if (req.session && req.session.user && req.session.user.isAdmin) {
    next();
  } else {
    res.status(403).json({ error: 'Admin access required' });
  }
};

// GET /api/admin/reported-content
router.get('/reported-content', adminMiddleware, async (req, res) => {
  try {
    const reportedPosts = await Post.find({ reported: true })
      .populate('author', 'username profile.firstName profile.lastName')
      .sort({ createdAt: -1 });
    
    const reportedComments = await Comment.find({ reported: true })
      .populate('author', 'username profile.firstName profile.lastName')
      .populate('postId', 'title')
      .sort({ createdAt: -1 });
    
    res.json({
      success: true,
      reportedPosts,
      reportedComments
    });
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;