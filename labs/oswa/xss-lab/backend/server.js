const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const morgan = require('morgan');
const path = require('path');
require('dotenv').config();

// Import routes
const authRoutes = require('./routes/auth');
const postRoutes = require('./routes/posts');
const commentRoutes = require('./routes/comments');
const userRoutes = require('./routes/users');
const searchRoutes = require('./routes/search');
const uploadRoutes = require('./routes/upload');
const adminRoutes = require('./routes/admin');

const app = express();
const PORT = process.env.PORT || 5000;

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('🔗 Connected to MongoDB'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// Middleware
app.use(morgan('combined'));

// CORS configuration - VULNERABLE: Too permissive for educational purposes
app.use(cors({
  origin: true, // Allows any origin - vulnerable
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept']
}));

// Body parsers
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Cookie parser
app.use(cookieParser());

// Session configuration - VULNERABLE: Weak session security
app.use(session({
  secret: process.env.SESSION_SECRET || 'vulnerable_session_secret',
  resave: false,
  saveUninitialized: true,
  cookie: { 
    secure: false, // Should be true in production with HTTPS
    httpOnly: false, // VULNERABLE: Allows JavaScript access to session cookies
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Static files for uploads
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Content Security Policy - VULNERABLE: Weak CSP for educational purposes
app.use((req, res, next) => {
  // Weak CSP that can be bypassed
  res.setHeader('Content-Security-Policy', 
    "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:; " +
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob: https:; " +
    "style-src 'self' 'unsafe-inline' data:; " +
    "img-src 'self' data: blob: https:; " +
    "connect-src 'self' https: ws: wss:;"
  );
  next();
});

// Custom middleware to log requests for debugging
app.use((req, res, next) => {
  console.log(`📝 ${new Date().toISOString()} - ${req.method} ${req.originalUrl}`);
  if (Object.keys(req.query).length > 0) {
    console.log('   Query params:', req.query);
  }
  if (req.body && Object.keys(req.body).length > 0) {
    console.log('   Body:', req.body);
  }
  next();
});

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/posts', postRoutes);
app.use('/api/comments', commentRoutes);
app.use('/api/users', userRoutes);
app.use('/api/search', searchRoutes);
app.use('/api/upload', uploadRoutes);
app.use('/api/admin', adminRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage()
  });
});

// VULNERABLE ENDPOINT: Direct XSS reflection for educational purposes
app.get('/vulnerable/reflect', (req, res) => {
  const userInput = req.query.input || 'No input provided';
  
  // VULNERABILITY: Direct reflection without encoding/escaping
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>XSS Lab - Reflection Test</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 600px; margin: 0 auto; }
        .input { background: #f0f0f0; padding: 20px; border-radius: 5px; }
        .flag { color: #d63384; font-weight: bold; display: none; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>🔍 Reflection Test Page</h1>
        <p>You searched for: <strong>${userInput}</strong></p>
        <div class="input">
          <p>Raw input: ${userInput}</p>
        </div>
        <div class="flag" id="hidden-flag">
          FLAG{R3FL3CT3D_XSS_M4ST3R}
        </div>
        <script>
          // Show flag if XSS is successful
          if (document.location.hash === '#xss-success') {
            document.getElementById('hidden-flag').style.display = 'block';
          }
        </script>
      </div>
    </body>
    </html>
  `;
  
  res.send(html);
});

// VULNERABLE ENDPOINT: DOM XSS through fragment manipulation
app.get('/vulnerable/dom', (req, res) => {
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>XSS Lab - DOM XSS</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 600px; margin: 0 auto; }
        .welcome { background: #e3f2fd; padding: 20px; border-radius: 5px; }
        .flag { color: #d63384; font-weight: bold; display: none; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>🏠 Welcome Page</h1>
        <div class="welcome" id="welcome-message">
          Welcome, Guest!
        </div>
        <p>Use URL fragment to set your name: #YourName</p>
        <div class="flag" id="dom-flag">
          FLAG{D0M_XSS_CSP_BYP4SS_L33T}
        </div>
      </div>
      
      <script>
        function updateWelcome() {
          const name = location.hash.substring(1);
          if (name) {
            // VULNERABILITY: Direct DOM manipulation without sanitization
            document.getElementById('welcome-message').innerHTML = 'Welcome, ' + decodeURIComponent(name) + '!';
            
            // Show flag if DOM XSS is triggered
            if (name.includes('script') || name.includes('img') || name.includes('svg')) {
              setTimeout(() => {
                document.getElementById('dom-flag').style.display = 'block';
              }, 1000);
            }
          }
        }
        
        // Update on hash change
        window.addEventListener('hashchange', updateWelcome);
        
        // Update on page load
        updateWelcome();
      </script>
    </body>
    </html>
  `;
  
  res.send(html);
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('🚨 Error:', err.stack);
  
  // In development, show detailed errors (VULNERABLE)
  if (process.env.NODE_ENV === 'development') {
    res.status(500).json({
      error: err.message,
      stack: err.stack,
      timestamp: new Date().toISOString()
    });
  } else {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 OSWA XSS Lab Backend running on port ${PORT}`);
  console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 MongoDB: ${process.env.MONGO_URI ? 'Connected' : 'Not configured'}`);
  console.log(`⚠️  SECURITY WARNING: This server contains intentional vulnerabilities for educational purposes!`);
});

module.exports = app;