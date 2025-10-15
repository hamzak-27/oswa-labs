const express = require('express');
const router = express.Router();
const Comment = require('../models/Comment');
const Post = require('../models/Post');
const User = require('../models/User');

// Middleware to check if user is authenticated (simplified for lab purposes)
const authMiddleware = (req, res, next) => {
  // In real application, this would verify JWT token
  // For lab purposes, we'll use session-based auth
  if (req.session && req.session.user) {
    req.user = req.session.user;
    next();
  } else {
    // Allow anonymous comments for testing purposes (VULNERABLE)
    req.user = {
      _id: '507f1f77bcf86cd799439014', // Default to charlie user
      username: 'anonymous',
      isAdmin: false
    };
    next();
  }
};

// GET /api/comments/:postId - Get comments for a post
router.get('/:postId', async (req, res) => {
  try {
    const postId = req.params.postId;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    
    // Verify post exists
    const post = await Post.findById(postId);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }
    
    // Get comments with replies
    const comments = await Comment.findByPost(postId, { page, limit });
    
    // Get replies for each comment
    const commentsWithReplies = await Promise.all(
      comments.map(async (comment) => {
        const replies = await Comment.findReplies(comment._id);
        return {
          ...comment.toObject(),
          replies: replies
        };
      })
    );
    
    res.json({
      success: true,
      comments: commentsWithReplies,
      pagination: {
        page,
        limit,
        total: await Comment.countDocuments({ postId, parentComment: null, isDeleted: false })
      }
    });
    
  } catch (error) {
    console.error('❌ Get comments error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// POST /api/comments - Create new comment (VULNERABLE to Stored XSS)
router.post('/', authMiddleware, async (req, res) => {
  try {
    const { postId, content, parentComment } = req.body;
    
    console.log(`💬 New comment from ${req.user.username}:`, content);
    
    // Basic validation
    if (!postId || !content) {
      return res.status(400).json({
        success: false,
        error: 'Post ID and content are required'
      });
    }
    
    // Verify post exists
    const post = await Post.findById(postId);
    if (!post) {
      return res.status(404).json({
        success: false,
        error: 'Post not found'
      });
    }
    
    // VULNERABILITY: No input sanitization or XSS protection
    // Content is stored as-is, allowing HTML/JavaScript injection
    const comment = new Comment({
      postId,
      content: content, // VULNERABLE: Direct storage without sanitization
      author: req.user._id,
      authorUsername: req.user.username,
      parentComment: parentComment || null,
      metadata: {
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        source: 'web'
      }
    });
    
    await comment.save();
    
    // Populate author info for response
    await comment.populate('author', 'username profile.firstName profile.lastName profile.avatar');
    
    // Mark post as reported if comment contains potential XSS
    if (content.includes('<script>') || content.includes('javascript:') || content.includes('onerror=')) {
      post.reported = true;
      await post.save();
      console.log('⚠️  Post marked as reported due to suspicious comment content');
    }
    
    res.status(201).json({
      success: true,
      comment: comment,
      message: 'Comment created successfully'
    });
    
  } catch (error) {
    console.error('❌ Create comment error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      // VULNERABLE: Debug info in production
      debug: {
        body: req.body,
        user: req.user.username
      }
    });
  }
});

// GET /api/comments/post/:postId/html - Get comments as HTML (VULNERABLE)
router.get('/post/:postId/html', async (req, res) => {
  try {
    const postId = req.params.postId;
    
    const comments = await Comment.find({ 
      postId, 
      parentComment: null, 
      isDeleted: false 
    })
    .populate('author', 'username profile.firstName profile.lastName profile.avatar')
    .sort({ createdAt: -1 });
    
    // VULNERABILITY: Generate HTML with unsanitized user content
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Comments - SecureShare</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 20px; background: #f8f9fa; }
            .comment-container { max-width: 800px; margin: 0 auto; }
            .comment { background: white; padding: 20px; margin-bottom: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .comment-header { display: flex; align-items: center; margin-bottom: 10px; }
            .comment-author { font-weight: 600; color: #2563eb; margin-right: 10px; }
            .comment-date { color: #6b7280; font-size: 14px; }
            .comment-content { line-height: 1.6; color: #374151; }
            .admin-badge { background: #dc2626; color: white; padding: 2px 6px; border-radius: 3px; font-size: 12px; margin-left: 5px; }
            .flag { background: #dc2626; color: white; padding: 10px; border-radius: 5px; margin: 20px 0; display: none; }
        </style>
        <script>
            // Admin simulation - check for admin cookies
            function checkAdminAccess() {
                const adminCookie = document.cookie.includes('admin_session=true');
                if (adminCookie) {
                    document.getElementById('admin-flag').style.display = 'block';
                }
            }
            
            // Simulate admin bot behavior
            setTimeout(() => {
                // If this page was reported, simulate admin visiting
                if (window.location.search.includes('reported=true')) {
                    document.cookie = 'admin_session=true; path=/';
                    document.cookie = 'admin_token=flag_bearer_2024; path=/';
                    checkAdminAccess();
                }
            }, 2000);
        </script>
    </head>
    <body>
        <div class="comment-container">
            <h1>💬 Comments</h1>
            
            <div class="flag" id="admin-flag">
                🎯 ADMIN FLAG CAPTURED: FLAG{ST0R3D_XSS_C00K13_TH13F}
            </div>
            
            ${comments.map(comment => `
                <div class="comment">
                    <div class="comment-header">
                        <span class="comment-author">${comment.authorUsername}</span>
                        ${comment.author?.isAdmin ? '<span class="admin-badge">ADMIN</span>' : ''}
                        <span class="comment-date">${new Date(comment.createdAt).toLocaleString()}</span>
                    </div>
                    <div class="comment-content">
                        ${comment.content}
                    </div>
                </div>
            `).join('')}
            
            ${comments.length === 0 ? `
                <div class="comment" style="text-align: center; color: #6b7280;">
                    <p>No comments yet. Be the first to comment!</p>
                </div>
            ` : ''}
        </div>
        
        <script>
            checkAdminAccess();
        </script>
    </body>
    </html>
    `;
    
    res.send(html);
    
  } catch (error) {
    console.error('❌ Get comments HTML error:', error);
    res.status(500).send(`
        <h1>Error Loading Comments</h1>
        <p>Error: ${error.message}</p>
    `);
  }
});

// PUT /api/comments/:id - Update comment
router.put('/:id', authMiddleware, async (req, res) => {
  try {
    const commentId = req.params.id;
    const { content } = req.body;
    
    const comment = await Comment.findById(commentId);
    if (!comment) {
      return res.status(404).json({ error: 'Comment not found' });
    }
    
    // Check if user owns the comment or is admin
    if (comment.author.toString() !== req.user._id.toString() && !req.user.isAdmin) {
      return res.status(403).json({ error: 'Not authorized to edit this comment' });
    }
    
    // Save edit history
    comment.editHistory.push({
      content: comment.content,
      editedAt: new Date(),
      editReason: 'User edit'
    });
    
    // VULNERABILITY: No sanitization on update either
    comment.content = content;
    await comment.save();
    
    await comment.populate('author', 'username profile.firstName profile.lastName profile.avatar');
    
    res.json({
      success: true,
      comment: comment,
      message: 'Comment updated successfully'
    });
    
  } catch (error) {
    console.error('❌ Update comment error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// DELETE /api/comments/:id - Delete comment
router.delete('/:id', authMiddleware, async (req, res) => {
  try {
    const commentId = req.params.id;
    
    const comment = await Comment.findById(commentId);
    if (!comment) {
      return res.status(404).json({ error: 'Comment not found' });
    }
    
    // Check if user owns the comment or is admin
    if (comment.author.toString() !== req.user._id.toString() && !req.user.isAdmin) {
      return res.status(403).json({ error: 'Not authorized to delete this comment' });
    }
    
    // Soft delete
    comment.isDeleted = true;
    comment.deletedAt = new Date();
    comment.deletedBy = req.user._id;
    await comment.save();
    
    res.json({
      success: true,
      message: 'Comment deleted successfully'
    });
    
  } catch (error) {
    console.error('❌ Delete comment error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// POST /api/comments/:id/report - Report comment
router.post('/:id/report', authMiddleware, async (req, res) => {
  try {
    const commentId = req.params.id;
    const { reason } = req.body;
    
    const comment = await Comment.findById(commentId);
    if (!comment) {
      return res.status(404).json({ error: 'Comment not found' });
    }
    
    // Add report
    comment.reportedBy.push({
      user: req.user._id,
      reason: reason || 'Inappropriate content',
      reportedAt: new Date()
    });
    
    comment.reported = true;
    await comment.save();
    
    // Also mark the post as reported
    await Post.findByIdAndUpdate(comment.postId, { reported: true });
    
    console.log(`📢 Comment ${commentId} reported by ${req.user.username}: ${reason}`);
    
    res.json({
      success: true,
      message: 'Comment reported successfully'
    });
    
  } catch (error) {
    console.error('❌ Report comment error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

module.exports = router;