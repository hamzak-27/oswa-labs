const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');

// Mock Post and User models (we'll create proper models later)
const Post = require('../models/Post');
const User = require('../models/User');

// VULNERABLE SEARCH ENDPOINT - Reflected XSS
router.get('/', async (req, res) => {
  try {
    const query = req.query.q || '';
    const category = req.query.category || 'all';
    
    console.log(`🔍 Search request: "${query}" in category: ${category}`);
    
    // Simulate database search (vulnerable to NoSQL injection too)
    let searchResults = [];
    
    if (query.trim()) {
      // Basic search in posts
      const posts = await Post.find({
        $or: [
          { title: { $regex: query, $options: 'i' } },
          { content: { $regex: query, $options: 'i' } },
          { tags: { $in: [new RegExp(query, 'i')] } }
        ]
      }).populate('author', 'username profile.firstName profile.lastName');
      
      searchResults = posts.map(post => ({
        type: 'post',
        id: post._id,
        title: post.title,
        content: post.content.substring(0, 200) + '...',
        author: post.author,
        createdAt: post.createdAt,
        tags: post.tags,
        likes: post.likes || 0,
        views: post.views || 0
      }));
    }
    
    // VULNERABILITY 1: Reflected XSS in JSON response
    // The search query is reflected back without proper sanitization
    const response = {
      success: true,
      query: query, // VULNERABLE: Direct reflection
      category: category,
      results: searchResults,
      total: searchResults.length,
      timestamp: new Date().toISOString(),
      debug: {
        originalQuery: query, // VULNERABLE: Debug info exposes raw input
        sanitized: false,
        filtered: false
      }
    };
    
    res.json(response);
    
  } catch (error) {
    console.error('❌ Search error:', error);
    
    // VULNERABILITY 2: Error messages can leak information
    res.status(500).json({
      success: false,
      error: error.message, // VULNERABLE: Detailed error exposure
      query: req.query.q, // VULNERABLE: Reflects user input in error
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// VULNERABLE SEARCH RESULTS PAGE - HTML Response with XSS
router.get('/results', async (req, res) => {
  try {
    const query = req.query.q || '';
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    
    // Basic search
    let searchResults = [];
    if (query.trim()) {
      const posts = await Post.find({
        $or: [
          { title: { $regex: query, $options: 'i' } },
          { content: { $regex: query, $options: 'i' } }
        ]
      })
      .populate('author', 'username profile')
      .sort({ createdAt: -1 })
      .limit(limit)
      .skip((page - 1) * limit);
      
      searchResults = posts;
    }
    
    // VULNERABILITY 3: Generate HTML page with reflected XSS
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Search Results - SecureShare</title>
        <meta charset="utf-8">
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; background: #f8f9fa; }
            .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
            .header { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .search-info { color: #666; margin-bottom: 20px; }
            .result-card { background: white; padding: 20px; border-radius: 8px; margin-bottom: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .result-title { color: #2563eb; text-decoration: none; font-size: 18px; font-weight: 600; }
            .result-title:hover { text-decoration: underline; }
            .result-content { color: #374151; margin: 10px 0; line-height: 1.6; }
            .result-meta { color: #6b7280; font-size: 14px; }
            .no-results { text-align: center; color: #6b7280; padding: 40px; }
            .flag { background: #dc2626; color: white; padding: 10px; border-radius: 5px; margin: 20px 0; display: none; }
            .highlight { background-color: #fef3c7; padding: 2px 4px; border-radius: 3px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔍 Search Results</h1>
                <div class="search-info">
                    <!-- VULNERABILITY: Direct injection of user input -->
                    <p>Showing results for: <strong>${query}</strong></p>
                    <p>Found ${searchResults.length} results</p>
                </div>
            </div>
            
            <div class="flag" id="xss-flag">
                🎯 FLAG CAPTURED: FLAG{R3FL3CT3D_XSS_M4ST3R}
            </div>
            
            ${searchResults.length > 0 ? searchResults.map(post => `
                <div class="result-card">
                    <a href="/posts/${post._id}" class="result-title">${post.title}</a>
                    <div class="result-content">
                        ${post.content.substring(0, 200)}...
                    </div>
                    <div class="result-meta">
                        By ${post.author?.username || 'Unknown'} • ${new Date(post.createdAt).toLocaleDateString()}
                        • ${post.likes || 0} likes • ${post.views || 0} views
                    </div>
                </div>
            `).join('') : `
                <div class="no-results">
                    <h3>No results found</h3>
                    <p>Try searching with different keywords</p>
                </div>
            `}
            
            <script>
                // Show flag if XSS payload detected
                const params = new URLSearchParams(window.location.search);
                const query = params.get('q');
                
                if (query && (query.includes('<script>') || query.includes('javascript:') || query.includes('onerror='))) {
                    document.getElementById('xss-flag').style.display = 'block';
                }
                
                // Highlight search terms (VULNERABLE: Can execute scripts)
                if (query) {
                    const content = document.querySelectorAll('.result-content, .result-title');
                    content.forEach(el => {
                        // VULNERABILITY: innerHTML assignment with user input
                        el.innerHTML = el.innerHTML.replace(
                            new RegExp(query, 'gi'), 
                            '<span class="highlight">' + query + '</span>'
                        );
                    });
                }
            </script>
        </div>
    </body>
    </html>
    `;
    
    res.send(html);
    
  } catch (error) {
    console.error('❌ Search results error:', error);
    res.status(500).send(`
        <h1>Search Error</h1>
        <p>Error processing search for: ${req.query.q}</p>
        <p>Error: ${error.message}</p>
    `);
  }
});

// VULNERABLE AUTOCOMPLETE ENDPOINT
router.get('/autocomplete', async (req, res) => {
  try {
    const query = req.query.q || '';
    
    if (query.length < 2) {
      return res.json({ suggestions: [] });
    }
    
    // Get suggestions from posts and users
    const postSuggestions = await Post.find({
      title: { $regex: query, $options: 'i' }
    })
    .select('title')
    .limit(5);
    
    const userSuggestions = await User.find({
      username: { $regex: query, $options: 'i' }
    })
    .select('username profile.firstName profile.lastName')
    .limit(3);
    
    const suggestions = [
      ...postSuggestions.map(p => ({ 
        type: 'post', 
        text: p.title,
        // VULNERABILITY: Direct reflection in JSON
        highlight: p.title.replace(new RegExp(query, 'gi'), `<mark>${query}</mark>`)
      })),
      ...userSuggestions.map(u => ({ 
        type: 'user', 
        text: u.username,
        highlight: u.username.replace(new RegExp(query, 'gi'), `<mark>${query}</mark>`)
      }))
    ];
    
    res.json({
      query: query, // VULNERABLE: Direct reflection
      suggestions: suggestions
    });
    
  } catch (error) {
    res.status(500).json({
      error: error.message,
      query: req.query.q // VULNERABLE: Reflects user input in error
    });
  }
});

module.exports = router;