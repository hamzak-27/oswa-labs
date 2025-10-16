const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8080;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(morgan('combined'));

// Serve static files
app.use(express.static('public'));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'jwt-debugger',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// JWT Decode endpoint
app.post('/decode', (req, res) => {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({
        error: 'JWT token is required',
        success: false
      });
    }

    // Decode without verification to show structure
    const decoded = jwt.decode(token, { complete: true });
    
    if (!decoded) {
      return res.status(400).json({
        error: 'Invalid JWT token format',
        success: false
      });
    }

    res.json({
      success: true,
      header: decoded.header,
      payload: decoded.payload,
      signature: decoded.signature,
      raw: {
        header: token.split('.')[0],
        payload: token.split('.')[1],
        signature: token.split('.')[2] || ''
      }
    });

  } catch (error) {
    res.status(500).json({
      error: error.message,
      success: false
    });
  }
});

// JWT Verify endpoint (with various algorithms)
app.post('/verify', (req, res) => {
  try {
    const { token, secret, algorithm = 'HS256', publicKey } = req.body;
    
    if (!token) {
      return res.status(400).json({
        error: 'JWT token is required',
        success: false
      });
    }

    let key = secret;
    let options = { algorithms: [algorithm] };
    
    if (algorithm.startsWith('RS') && publicKey) {
      key = publicKey;
    }

    if (!key) {
      return res.status(400).json({
        error: 'Secret or public key is required for verification',
        success: false
      });
    }

    const verified = jwt.verify(token, key, options);
    
    res.json({
      success: true,
      verified: true,
      payload: verified,
      algorithm: algorithm
    });

  } catch (error) {
    res.json({
      success: true,
      verified: false,
      error: error.message,
      hint: 'Token verification failed - check your secret/key and algorithm'
    });
  }
});

// JWT Generate endpoint
app.post('/generate', (req, res) => {
  try {
    const { payload, secret, algorithm = 'HS256', privateKey, expiresIn } = req.body;
    
    if (!payload) {
      return res.status(400).json({
        error: 'Payload is required',
        success: false
      });
    }

    let key = secret;
    let options = {};
    
    if (algorithm.startsWith('RS') && privateKey) {
      key = privateKey;
    }

    if (!key) {
      return res.status(400).json({
        error: 'Secret or private key is required for signing',
        success: false
      });
    }

    if (expiresIn) {
      options.expiresIn = expiresIn;
    }

    const token = jwt.sign(payload, key, { algorithm, ...options });
    
    res.json({
      success: true,
      token: token,
      algorithm: algorithm,
      payload: payload
    });

  } catch (error) {
    res.status(500).json({
      error: error.message,
      success: false
    });
  }
});

// JWT Analysis endpoint - provides hints for common vulnerabilities
app.post('/analyze', (req, res) => {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({
        error: 'JWT token is required',
        success: false
      });
    }

    const decoded = jwt.decode(token, { complete: true });
    
    if (!decoded) {
      return res.status(400).json({
        error: 'Invalid JWT token format',
        success: false
      });
    }

    const analysis = {
      algorithm: decoded.header.alg,
      vulnerabilities: [],
      recommendations: [],
      security_score: 100
    };

    // Check for 'none' algorithm vulnerability
    if (decoded.header.alg === 'none') {
      analysis.vulnerabilities.push({
        type: 'none_algorithm',
        severity: 'critical',
        description: 'Token uses "none" algorithm - no signature verification',
        exploit_hint: 'Try accessing protected endpoints with this token'
      });
      analysis.security_score -= 50;
    }

    // Check for weak algorithms
    if (decoded.header.alg === 'HS256') {
      analysis.vulnerabilities.push({
        type: 'weak_secret_potential',
        severity: 'medium',
        description: 'HMAC-based algorithm - vulnerable to secret brute force',
        exploit_hint: 'Try cracking the secret with common passwords'
      });
      analysis.security_score -= 20;
    }

    // Check for algorithm confusion potential
    if (decoded.header.alg === 'RS256') {
      analysis.vulnerabilities.push({
        type: 'algorithm_confusion',
        severity: 'high',
        description: 'RSA algorithm - check for RS256/HS256 confusion vulnerability',
        exploit_hint: 'Try signing with public key using HS256'
      });
      analysis.security_score -= 30;
    }

    // Check for kid parameter
    if (decoded.header.kid) {
      analysis.vulnerabilities.push({
        type: 'kid_injection',
        severity: 'high',
        description: 'Contains kid parameter - potential path traversal vulnerability',
        exploit_hint: 'Try injecting "../../../etc/passwd" in kid parameter'
      });
      analysis.security_score -= 30;
    }

    // Check payload for sensitive data
    if (decoded.payload.password || decoded.payload.secret) {
      analysis.vulnerabilities.push({
        type: 'sensitive_data_exposure',
        severity: 'medium',
        description: 'Payload contains potentially sensitive information'
      });
      analysis.security_score -= 15;
    }

    res.json({
      success: true,
      analysis: analysis,
      token_structure: {
        header: decoded.header,
        payload: decoded.payload
      }
    });

  } catch (error) {
    res.status(500).json({
      error: error.message,
      success: false
    });
  }
});

// Serve the debugger UI
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>JWT Debugger - OSWA Lab</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
            .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
            .header { background: #333; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
            .section { margin: 20px 0; }
            textarea { width: 100%; height: 100px; font-family: monospace; }
            input[type="text"] { width: 100%; padding: 8px; margin: 5px 0; }
            button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin: 5px; }
            button:hover { background: #0056b3; }
            .result { background: #f8f9fa; padding: 15px; border-radius: 4px; margin: 10px 0; }
            .vulnerability { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 10px; border-radius: 4px; margin: 5px 0; }
            .critical { background: #dc3545; color: white; }
            .high { background: #fd7e14; color: white; }
            .medium { background: #ffc107; color: #212529; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔐 JWT Debugger - OSWA Lab</h1>
                <p>Analyze and debug JWT tokens for security vulnerabilities</p>
            </div>

            <div class="section">
                <h3>JWT Token Analysis</h3>
                <textarea id="token" placeholder="Paste your JWT token here..."></textarea>
                <button onclick="decodeToken()">Decode Token</button>
                <button onclick="analyzeToken()">Security Analysis</button>
            </div>

            <div class="section">
                <h3>Results</h3>
                <div id="results"></div>
            </div>

            <div class="section">
                <h3>JWT Generator</h3>
                <textarea id="payload" placeholder='{"sub": "1234567890", "name": "John Doe", "iat": 1516239022}'></textarea>
                <input type="text" id="secret" placeholder="Secret key">
                <select id="algorithm">
                    <option value="HS256">HS256</option>
                    <option value="HS384">HS384</option>
                    <option value="HS512">HS512</option>
                    <option value="none">none</option>
                </select>
                <button onclick="generateToken()">Generate Token</button>
            </div>
        </div>

        <script>
            async function decodeToken() {
                const token = document.getElementById('token').value;
                if (!token) return alert('Please enter a JWT token');

                try {
                    const response = await fetch('/decode', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ token })
                    });
                    
                    const result = await response.json();
                    displayResult(result);
                } catch (error) {
                    displayResult({ error: error.message, success: false });
                }
            }

            async function analyzeToken() {
                const token = document.getElementById('token').value;
                if (!token) return alert('Please enter a JWT token');

                try {
                    const response = await fetch('/analyze', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ token })
                    });
                    
                    const result = await response.json();
                    displayAnalysis(result);
                } catch (error) {
                    displayResult({ error: error.message, success: false });
                }
            }

            async function generateToken() {
                const payload = document.getElementById('payload').value;
                const secret = document.getElementById('secret').value;
                const algorithm = document.getElementById('algorithm').value;
                
                if (!payload || (!secret && algorithm !== 'none')) {
                    return alert('Please provide payload and secret');
                }

                try {
                    const payloadObj = JSON.parse(payload);
                    const response = await fetch('/generate', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ payload: payloadObj, secret, algorithm })
                    });
                    
                    const result = await response.json();
                    displayResult(result);
                } catch (error) {
                    displayResult({ error: error.message, success: false });
                }
            }

            function displayResult(result) {
                const resultsDiv = document.getElementById('results');
                resultsDiv.innerHTML = '<pre>' + JSON.stringify(result, null, 2) + '</pre>';
            }

            function displayAnalysis(result) {
                const resultsDiv = document.getElementById('results');
                let html = '<h4>Security Analysis</h4>';
                
                if (result.success && result.analysis) {
                    html += '<p><strong>Security Score: ' + result.analysis.security_score + '/100</strong></p>';
                    
                    if (result.analysis.vulnerabilities.length > 0) {
                        html += '<h5>Vulnerabilities Found:</h5>';
                        result.analysis.vulnerabilities.forEach(vuln => {
                            html += '<div class="vulnerability ' + vuln.severity + '">';
                            html += '<strong>' + vuln.type.toUpperCase() + ' (' + vuln.severity + ')</strong><br>';
                            html += vuln.description;
                            if (vuln.exploit_hint) {
                                html += '<br><em>Hint: ' + vuln.exploit_hint + '</em>';
                            }
                            html += '</div>';
                        });
                    } else {
                        html += '<p style="color: green;">No obvious vulnerabilities detected.</p>';
                    }
                }
                
                html += '<h5>Full Analysis:</h5><pre>' + JSON.stringify(result, null, 2) + '</pre>';
                resultsDiv.innerHTML = html;
            }
        </script>
    </body>
    </html>
  `);
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🔐 JWT Debugger running on port ${PORT}`);
  console.log(`🌐 Access at: http://localhost:${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
});

module.exports = app;