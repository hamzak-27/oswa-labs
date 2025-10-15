const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs-extra');
const path = require('path');
const crypto = require('crypto');
const morgan = require('morgan');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5001;

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('🔗 Connected to MongoDB'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// Import models
const User = require('./models/User');
const AuditLog = require('./models/AuditLog');
const Service = require('./models/Service');

// Middleware
app.use(morgan('combined'));
app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'X-API-Key']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Load RSA keys for JWT signing (if they exist)
let RSA_PRIVATE_KEY = null;
let RSA_PUBLIC_KEY = null;

try {
  if (fs.existsSync('/app/keys/rsa_private.pem')) {
    RSA_PRIVATE_KEY = fs.readFileSync('/app/keys/rsa_private.pem', 'utf8');
    RSA_PUBLIC_KEY = fs.readFileSync('/app/keys/rsa_public.pem', 'utf8');
    console.log('✅ RSA keys loaded successfully');
  }
} catch (error) {
  console.log('⚠️  RSA keys not found, using HMAC only');
}

// JWT Utilities with VULNERABILITIES
const JWTUtils = {
  // VULNERABILITY 1: Multiple algorithms supported without proper validation
  sign: (payload, options = {}) => {
    const algorithm = options.algorithm || 'HS256';
    const secret = options.secret || process.env.JWT_SECRET_WEAK;
    
    console.log(`🔐 Signing JWT with algorithm: ${algorithm}`);
    
    try {
      switch (algorithm) {
        case 'HS256':
        case 'HS512':
          return jwt.sign(payload, secret, { algorithm, expiresIn: '1h', ...options });
        
        case 'RS256':
          if (!RSA_PRIVATE_KEY) {
            throw new Error('RSA private key not available');
          }
          return jwt.sign(payload, RSA_PRIVATE_KEY, { algorithm, expiresIn: '1h', ...options });
        
        case 'none':
          // VULNERABILITY: 'none' algorithm support
          const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
          const payloadBase64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
          return `${header}.${payloadBase64}.`;
        
        default:
          throw new Error(`Unsupported algorithm: ${algorithm}`);
      }
    } catch (error) {
      console.error('JWT signing error:', error);
      throw error;
    }
  },

  // VULNERABILITY 2: Weak verification logic
  verify: (token, options = {}) => {
    try {
      // Extract header to check algorithm
      const [headerB64] = token.split('.');
      const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());
      
      console.log(`🔍 Verifying JWT with algorithm: ${header.alg}`);
      
      // VULNERABILITY: Accept algorithm from token header without validation
      switch (header.alg) {
        case 'none':
          // VULNERABILITY: Accept 'none' algorithm
          const [, payloadB64] = token.split('.');
          const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
          console.log('⚠️  WARNING: Accepting unsigned JWT token!');
          return payload;
        
        case 'HS256':
        case 'HS512':
          // VULNERABILITY: Use weak secret by default
          const secret = options.secret || process.env.JWT_SECRET_WEAK;
          return jwt.verify(token, secret);
        
        case 'RS256':
          // VULNERABILITY: Algorithm confusion - might accept RS256 token with HS256 verification
          if (options.forceHMAC || !RSA_PUBLIC_KEY) {
            console.log('⚠️  WARNING: Verifying RS256 token with HMAC!');
            // This is the critical vulnerability - using RSA public key as HMAC secret
            return jwt.verify(token, RSA_PUBLIC_KEY, { algorithms: ['HS256'] });
          }
          return jwt.verify(token, RSA_PUBLIC_KEY);
        
        default:
          throw new Error(`Unsupported algorithm: ${header.alg}`);
      }
    } catch (error) {
      console.error('JWT verification error:', error.message);
      throw error;
    }
  },

  // VULNERABILITY 3: Kid parameter file inclusion
  verifyWithKid: (token) => {
    try {
      const [headerB64] = token.split('.');
      const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());
      
      if (header.kid) {
        console.log(`🔑 Using kid parameter: ${header.kid}`);
        
        // VULNERABILITY: Path traversal in kid parameter
        let keyPath = header.kid;
        
        // Basic attempt at sanitization (easily bypassed)
        if (!keyPath.includes('../') && !keyPath.includes('..\\')) {
          try {
            // VULNERABILITY: Read arbitrary files based on kid parameter
            const keyContent = fs.readFileSync(path.join('/app/keys', keyPath), 'utf8');
            
            // Check if it's a flag file
            if (keyContent.includes('FLAG{')) {
              console.log('🎯 FLAG DISCOVERED VIA KID PARAMETER!');
              return { flag: keyContent.match(/FLAG\{[^}]+\}/)[0] };
            }
            
            return jwt.verify(token, keyContent);
          } catch (fileError) {
            console.error('Kid file read error:', fileError.message);
            // Fallback to default verification
            return JWTUtils.verify(token);
          }
        } else {
          console.log('⚠️  Kid parameter contains path traversal, using default key');
          return JWTUtils.verify(token);
        }
      }
      
      return JWTUtils.verify(token);
    } catch (error) {
      throw error;
    }
  }
};

// Authentication middleware with vulnerabilities
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
  
  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }
  
  try {
    // VULNERABILITY: Try multiple verification methods
    let decoded;
    
    // First try with kid parameter (vulnerable to path traversal)
    try {
      decoded = JWTUtils.verifyWithKid(token);
      
      // Check if we got a flag from kid parameter injection
      if (decoded.flag) {
        return res.json({
          success: true,
          flag: decoded.flag,
          message: 'FLAG{JWT_1NJ3CT10N_V1A_K1D_CL41M}',
          vulnerability: 'Kid parameter injection'
        });
      }
    } catch (kidError) {
      // Fallback to normal verification
      decoded = JWTUtils.verify(token, { forceHMAC: req.query.force_hmac === 'true' });
    }
    
    req.user = decoded;
    
    // Log the authentication attempt
    AuditLog.create({
      event_type: 'token_validation',
      user_id: decoded.sub,
      username: decoded.username || 'unknown',
      success: true,
      jwt_algorithm: decoded.alg || 'unknown',
      ip_address: req.ip,
      user_agent: req.get('User-Agent'),
      timestamp: new Date(),
      details: {
        token_claims: decoded,
        headers: req.headers
      }
    }).catch(err => console.error('Audit log error:', err));
    
    next();
  } catch (error) {
    console.error('Authentication error:', error.message);
    
    // Log failed attempt
    AuditLog.create({
      event_type: 'token_validation',
      success: false,
      jwt_algorithm: 'unknown',
      ip_address: req.ip,
      user_agent: req.get('User-Agent'),
      timestamp: new Date(),
      details: {
        error: error.message,
        token_preview: token.substring(0, 50) + '...'
      }
    }).catch(err => console.error('Audit log error:', err));
    
    return res.status(403).json({ 
      error: 'Invalid token',
      debug: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Routes

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    service: 'JWT Attacks Lab',
    timestamp: new Date().toISOString(),
    jwt_algorithms_supported: ['HS256', 'HS512', 'RS256', 'none'],
    vulnerabilities_active: ['none_alg', 'weak_secret', 'algorithm_confusion', 'kid_injection']
  });
});

// Login endpoint with multiple JWT generation options
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password, algorithm, use_weak_secret } = req.body;
    
    console.log(`🔐 Login attempt: ${username} with algorithm: ${algorithm || 'default'}`);
    
    // Find user
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    if (!user.is_active) {
      return res.status(401).json({ error: 'Account disabled' });
    }
    
    // Prepare JWT payload
    const payload = {
      sub: user._id,
      username: user.username,
      role: user.role,
      permissions: user.permissions,
      iat: Math.floor(Date.now() / 1000),
      version: user.jwt_version || 1
    };
    
    // VULNERABILITY: Allow client to specify algorithm and secret strength
    const jwtOptions = {
      algorithm: algorithm || 'HS256',
      secret: use_weak_secret ? 'weak_secret_123' : process.env.JWT_SECRET_STRONG,
      expiresIn: '1h'
    };
    
    const token = JWTUtils.sign(payload, jwtOptions);
    
    // Update last login
    user.last_login = new Date();
    await user.save();
    
    // Log successful login
    await AuditLog.create({
      event_type: 'login_attempt',
      user_id: user._id,
      username: user.username,
      success: true,
      jwt_algorithm: jwtOptions.algorithm,
      ip_address: req.ip,
      user_agent: req.get('User-Agent'),
      timestamp: new Date(),
      details: {
        permissions_granted: user.permissions,
        token_version: user.jwt_version
      }
    });
    
    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        role: user.role,
        permissions: user.permissions
      },
      algorithm_used: jwtOptions.algorithm,
      debug_info: {
        weak_secret_used: use_weak_secret,
        token_preview: token.substring(0, 50) + '...'
      }
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed', details: error.message });
  }
});

// Protected profile endpoint
app.get('/api/user/profile', authenticateJWT, async (req, res) => {
  try {
    const user = await User.findById(req.user.sub);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        permissions: user.permissions,
        profile: user.profile,
        secret_data: user.secret_data // VULNERABILITY: Expose sensitive data
      },
      jwt_claims: req.user
    });
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin endpoint (requires admin role)
app.get('/api/admin/users', authenticateJWT, async (req, res) => {
  try {
    // VULNERABILITY: Insufficient role validation
    if (!req.user.permissions || !req.user.permissions.includes('admin')) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const users = await User.find({}).select('-password');
    
    res.json({
      success: true,
      users,
      admin_flag: 'FLAG{JWT_ADMIN_PRIVILEGE_ESCALATION}',
      message: 'Admin access granted via JWT claims'
    });
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// JWT debugging endpoint (VULNERABLE)
app.post('/api/jwt/debug', (req, res) => {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({ error: 'Token required' });
    }
    
    // Parse JWT without verification for debugging
    const [headerB64, payloadB64, signature] = token.split('.');
    
    const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
    
    // VULNERABILITY: Expose internal implementation details
    const debugInfo = {
      token_structure: {
        header,
        payload,
        signature: signature || 'none'
      },
      algorithm: header.alg,
      key_id: header.kid || null,
      expires_at: payload.exp ? new Date(payload.exp * 1000) : null,
      issued_at: payload.iat ? new Date(payload.iat * 1000) : null,
      validation_hints: {
        none_algorithm: header.alg === 'none' ? 'Token uses none algorithm - no signature required' : null,
        weak_secret: header.alg === 'HS256' ? 'Try brute forcing with common passwords' : null,
        rsa_confusion: header.alg === 'RS256' ? 'Try using public key as HMAC secret' : null,
        kid_injection: header.kid ? 'Kid parameter might be vulnerable to path traversal' : null
      },
      system_info: {
        jwt_secret_hint: process.env.JWT_SECRET_WEAK.substring(0, 4) + '***',
        rsa_keys_available: !!RSA_PUBLIC_KEY,
        supported_algorithms: ['HS256', 'HS512', 'RS256', 'none']
      }
    };
    
    // Check for flags based on token content
    if (header.alg === 'none') {
      debugInfo.flag = 'FLAG{JWT_N0N3_4LG0R1THM_BYP4SS}';
    }
    
    res.json({
      success: true,
      debug: debugInfo
    });
    
  } catch (error) {
    res.status(500).json({ 
      error: 'Debug failed',
      details: error.message,
      hint: 'Invalid JWT format'
    });
  }
});

// Vulnerable token refresh endpoint
app.post('/api/auth/refresh', (req, res) => {
  try {
    const { refresh_token, new_algorithm } = req.body;
    
    // VULNERABILITY: Accept algorithm change during refresh
    const decoded = JWTUtils.verify(refresh_token);
    
    // Generate new token with potentially different algorithm
    const newToken = JWTUtils.sign({
      sub: decoded.sub,
      username: decoded.username,
      role: decoded.role,
      permissions: decoded.permissions,
      version: decoded.version
    }, {
      algorithm: new_algorithm || 'HS256',
      secret: process.env.JWT_SECRET_WEAK
    });
    
    res.json({
      success: true,
      token: newToken,
      algorithm_used: new_algorithm || 'HS256'
    });
    
  } catch (error) {
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});

// Get RSA public key (for algorithm confusion attacks)
app.get('/api/jwt/pubkey', (req, res) => {
  if (!RSA_PUBLIC_KEY) {
    return res.status(404).json({ error: 'RSA keys not available' });
  }
  
  res.json({
    success: true,
    public_key: RSA_PUBLIC_KEY,
    algorithm: 'RS256',
    hint: 'This key might be useful for algorithm confusion attacks...'
  });
});

// Secret cracking challenge endpoint
app.get('/api/jwt/crack-challenge', (req, res) => {
  // Generate a JWT with an intentionally weak secret
  const weakSecrets = ['123', 'password', 'secret', 'admin', 'test', 'weak_secret_123'];
  const randomSecret = weakSecrets[Math.floor(Math.random() * weakSecrets.length)];
  
  const challengeToken = jwt.sign({
    challenge: 'crack_me',
    flag: 'FLAG{JWT_W34K_S3CR3T_CR4CK3D}',
    hint: 'This token uses a very weak secret...'
  }, randomSecret, {
    algorithm: 'HS256',
    expiresIn: '1h'
  });
  
  res.json({
    success: true,
    challenge_token: challengeToken,
    task: 'Crack this JWT secret to reveal the flag',
    hint: 'Try common passwords and dictionary attacks'
  });
});

// Error handling
app.use((err, req, res, next) => {
  console.error('🚨 Error:', err.stack);
  res.status(500).json({
    error: 'Internal server error',
    debug: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 OSWA JWT Attacks Lab Backend running on port ${PORT}`);
  console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 MongoDB: ${process.env.MONGO_URI ? 'Connected' : 'Not configured'}`);
  console.log(`🔑 RSA Keys: ${RSA_PUBLIC_KEY ? 'Available' : 'Not available'}`);
  console.log(`⚠️  SECURITY WARNING: This server contains intentional JWT vulnerabilities!`);
  console.log(`🎯 Attack vectors: none algorithm, weak secrets, algorithm confusion, kid injection`);
});

module.exports = app;