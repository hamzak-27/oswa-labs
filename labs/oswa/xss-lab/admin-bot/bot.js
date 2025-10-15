const puppeteer = require('puppeteer');
const express = require('express');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://frontend:3000';
const BACKEND_URL = process.env.BACKEND_URL || 'http://backend:5000';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const BOT_INTERVAL = parseInt(process.env.BOT_INTERVAL) || 30000; // 30 seconds

console.log('🤖 OSWA XSS Lab Admin Bot starting...');
console.log(`📡 Frontend URL: ${FRONTEND_URL}`);
console.log(`🔗 Backend URL: ${BACKEND_URL}`);
console.log(`⏱️  Check interval: ${BOT_INTERVAL}ms`);

let browser;
let visitQueue = [];
let isProcessingQueue = false;

// Initialize Puppeteer browser
async function initBrowser() {
  try {
    browser = await puppeteer.launch({
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--no-first-run',
        '--no-zygote',
        '--single-process',
        '--disable-gpu'
      ]
    });
    console.log('✅ Admin bot browser initialized');
  } catch (error) {
    console.error('❌ Failed to initialize browser:', error);
  }
}

// Simulate admin login and visit reported content
async function visitReportedContent(postId, reportReason = 'Suspicious content detected') {
  if (!browser) {
    console.log('⚠️  Browser not initialized, skipping visit');
    return false;
  }

  const page = await browser.newPage();
  
  try {
    console.log(`👨‍💼 Admin bot visiting reported content: ${postId}`);
    
    // Set admin cookies to simulate logged-in admin user
    await page.setCookie(
      {
        name: 'admin_session',
        value: 'true',
        domain: 'localhost',
        path: '/',
        httpOnly: false,
        secure: false
      },
      {
        name: 'admin_token',
        value: 'flag_bearer_2024',
        domain: 'localhost',
        path: '/',
        httpOnly: false,
        secure: false
      },
      {
        name: 'user_role',
        value: 'admin',
        domain: 'localhost', 
        path: '/',
        httpOnly: false,
        secure: false
      }
    );

    // Visit the comments page with admin privileges
    const commentsUrl = `${BACKEND_URL}/api/comments/post/${postId}/html?reported=true`;
    console.log(`🌐 Navigating to: ${commentsUrl}`);
    
    const response = await page.goto(commentsUrl, { 
      waitUntil: 'networkidle2',
      timeout: 10000 
    });

    if (response.ok()) {
      console.log('✅ Admin successfully visited reported content');
      
      // Wait for potential XSS execution
      await page.waitForTimeout(3000);
      
      // Check for XSS execution indicators
      const pageContent = await page.content();
      if (pageContent.includes('<script>') || pageContent.includes('onerror=')) {
        console.log('🚨 Potential XSS detected in content');
        
        // Simulate admin being compromised
        await page.evaluate(() => {
          // If XSS executed, it would have access to admin cookies
          const adminToken = document.cookie;
          console.log('🔓 Admin session potentially compromised:', adminToken);
        });
      }
      
      return true;
    } else {
      console.log(`❌ Failed to load content: ${response.status()}`);
      return false;
    }
    
  } catch (error) {
    console.error('❌ Error during admin visit:', error.message);
    return false;
  } finally {
    await page.close();
  }
}

// Check for reported posts that need admin review
async function checkReportedPosts() {
  try {
    // In a real scenario, this would check for posts marked as reported
    const reportedPosts = [
      '608f1f77bcf86cd799439021', // Default post ID for testing
      '608f1f77bcf86cd799439022',
      '608f1f77bcf86cd799439023',
      '608f1f77bcf86cd799439024'
    ];

    for (const postId of reportedPosts) {
      visitQueue.push({
        postId,
        timestamp: Date.now(),
        reason: 'Scheduled admin review'
      });
    }
    
  } catch (error) {
    console.error('❌ Error checking reported posts:', error);
  }
}

// Process visit queue
async function processVisitQueue() {
  if (isProcessingQueue || visitQueue.length === 0) {
    return;
  }
  
  isProcessingQueue = true;
  console.log(`📋 Processing ${visitQueue.length} items in visit queue`);
  
  while (visitQueue.length > 0) {
    const item = visitQueue.shift();
    console.log(`🔄 Processing visit for post: ${item.postId}`);
    
    await visitReportedContent(item.postId, item.reason);
    
    // Wait between visits to simulate human behavior
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  
  isProcessingQueue = false;
  console.log('✅ Queue processing complete');
}

// API endpoint to trigger manual admin visit
app.use(express.json());

app.post('/visit', async (req, res) => {
  const { postId, reason } = req.body;
  
  if (!postId) {
    return res.status(400).json({ error: 'postId is required' });
  }
  
  visitQueue.push({
    postId,
    timestamp: Date.now(),
    reason: reason || 'Manual admin visit triggered'
  });
  
  console.log(`📥 Manual visit queued for post: ${postId}`);
  
  res.json({ 
    success: true, 
    message: 'Admin visit queued',
    queueLength: visitQueue.length 
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    browser: browser ? 'initialized' : 'not_initialized',
    queueLength: visitQueue.length,
    isProcessing: isProcessingQueue
  });
});

// Status endpoint
app.get('/status', (req, res) => {
  res.json({
    uptime: process.uptime(),
    visitQueue: visitQueue.length,
    isProcessingQueue,
    lastVisit: visitQueue.length > 0 ? visitQueue[visitQueue.length - 1].timestamp : null,
    browserStatus: browser ? 'active' : 'inactive'
  });
});

// Start the admin bot
async function startAdminBot() {
  try {
    // Initialize browser
    await initBrowser();
    
    // Start HTTP server
    app.listen(PORT, () => {
      console.log(`🚀 Admin Bot API running on port ${PORT}`);
    });
    
    // Start periodic checking for reported posts
    setInterval(async () => {
      await checkReportedPosts();
      await processVisitQueue();
    }, BOT_INTERVAL);
    
    console.log('✅ Admin bot fully initialized and running');
    
  } catch (error) {
    console.error('❌ Failed to start admin bot:', error);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('🛑 Admin bot shutting down...');
  if (browser) {
    await browser.close();
  }
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('🛑 Admin bot terminating...');
  if (browser) {
    await browser.close();
  }
  process.exit(0);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
});

// Start the admin bot
startAdminBot();