const express = require('express');
const router = express.Router();

// Mock authentication for testing
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Simple mock authentication
    if (username && password) {
      const user = {
        id: 1,
        username,
        email: `${username}@oswa.local`,
        role: 'student',
        created_at: new Date()
      };
      
      res.json({
        success: true,
        message: 'Login successful',
        user,
        token: 'mock_jwt_token'
      });
    } else {
      res.status(400).json({
        success: false,
        message: 'Username and password required'
      });
    }
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Login failed',
      error: error.message
    });
  }
});

router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    const user = {
      id: Math.floor(Math.random() * 1000),
      username,
      email,
      role: 'student',
      created_at: new Date()
    };
    
    res.json({
      success: true,
      message: 'Registration successful',
      user
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Registration failed',
      error: error.message
    });
  }
});

router.get('/me', async (req, res) => {
  res.json({
    success: true,
    user: {
      id: 1,
      username: 'testuser',
      email: 'testuser@oswa.local',
      role: 'student'
    }
  });
});

router.post('/logout', async (req, res) => {
  res.json({
    success: true,
    message: 'Logout successful'
  });
});

module.exports = router;