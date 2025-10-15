const jwt = require('jsonwebtoken');
const User = require('../models/User');
const logger = require('../utils/logger');

const authMiddleware = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '') || 
                  req.cookies?.token ||
                  req.session?.token;

    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'Access denied. No token provided.',
        code: 'NO_TOKEN'
      });
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'lab_management_secret');
      
      // Get user from database to ensure account is still active
      const user = await User.findById(decoded.id).select('-password');
      
      if (!user) {
        return res.status(401).json({
          success: false,
          error: 'Token is valid but user no longer exists',
          code: 'USER_NOT_FOUND'
        });
      }

      if (!user.isActive) {
        return res.status(401).json({
          success: false,
          error: 'Account has been deactivated',
          code: 'ACCOUNT_DEACTIVATED'
        });
      }

      if (user.isLocked) {
        return res.status(401).json({
          success: false,
          error: 'Account is temporarily locked',
          code: 'ACCOUNT_LOCKED'
        });
      }

      // Update last active timestamp
      user.lastActiveAt = new Date();
      await user.save();

      // Add user to request object
      req.user = user;
      next();

    } catch (jwtError) {
      logger.security('warn', 'Invalid JWT token', null, {
        token: token.substring(0, 20) + '...',
        error: jwtError.message,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      return res.status(401).json({
        success: false,
        error: 'Invalid token',
        code: 'INVALID_TOKEN'
      });
    }

  } catch (error) {
    logger.error('Authentication middleware error:', error);
    return res.status(500).json({
      success: false,
      error: 'Authentication failed',
      code: 'AUTH_ERROR'
    });
  }
};

// Middleware to check for admin role
const adminMiddleware = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    logger.security('warn', 'Unauthorized admin access attempt', req.user?.id, {
      role: req.user?.role,
      endpoint: req.originalUrl,
      ip: req.ip
    });

    return res.status(403).json({
      success: false,
      error: 'Admin access required',
      code: 'INSUFFICIENT_PERMISSIONS'
    });
  }
};

// Middleware to check for instructor or admin role
const instructorMiddleware = (req, res, next) => {
  if (req.user && (req.user.role === 'instructor' || req.user.role === 'admin')) {
    next();
  } else {
    return res.status(403).json({
      success: false,
      error: 'Instructor or admin access required',
      code: 'INSUFFICIENT_PERMISSIONS'
    });
  }
};

// Optional auth middleware - doesn't fail if no token
const optionalAuthMiddleware = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '') || 
                  req.cookies?.token ||
                  req.session?.token;

    if (token) {
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'lab_management_secret');
        const user = await User.findById(decoded.id).select('-password');
        
        if (user && user.isActive && !user.isLocked) {
          req.user = user;
          user.lastActiveAt = new Date();
          await user.save();
        }
      } catch (jwtError) {
        // Silently ignore invalid tokens in optional auth
      }
    }

    next();
  } catch (error) {
    // Don't fail the request for optional auth errors
    next();
  }
};

module.exports = {
  authMiddleware,
  adminMiddleware,
  instructorMiddleware,
  optionalAuthMiddleware
};