const express = require('express');
const router = express.Router();
const Post = require('../models/Post');

// GET /api/posts - Get all posts
router.get('/', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    
    const posts = await Post.findRecent(limit)
      .skip((page - 1) * limit);
    
    const total = await Post.countDocuments({ visibility: 'public' });
    
    res.json({
      success: true,
      posts,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
    
  } catch (error) {
    console.error('❌ Get posts error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// GET /api/posts/:id - Get single post
router.get('/:id', async (req, res) => {
  try {
    const post = await Post.findById(req.params.id)
      .populate('author', 'username profile.firstName profile.lastName profile.avatar');
    
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }
    
    // Increment views
    await post.incrementViews();
    
    res.json({
      success: true,
      post
    });
    
  } catch (error) {
    console.error('❌ Get post error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

module.exports = router;