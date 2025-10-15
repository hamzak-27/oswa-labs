const winston = require('winston');
const path = require('path');

// Create logs directory if it doesn't exist
const fs = require('fs');
const logDir = path.join(__dirname, '../logs');
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

// Custom log format
const logFormat = winston.format.combine(
  winston.format.timestamp({
    format: 'YYYY-MM-DD HH:mm:ss'
  }),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

// Console format for development
const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({
    format: 'YYYY-MM-DD HH:mm:ss'
  }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    const metaString = Object.keys(meta).length ? JSON.stringify(meta, null, 2) : '';
    return `${timestamp} [${level}]: ${message} ${metaString}`;
  })
);

// Create Winston logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: logFormat,
  defaultMeta: { 
    service: 'oswa-lab-management',
    version: '1.0.0'
  },
  transports: [
    // Error log file
    new winston.transports.File({
      filename: path.join(logDir, 'error.log'),
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
    
    // Combined log file
    new winston.transports.File({
      filename: path.join(logDir, 'combined.log'),
      maxsize: 5242880, // 5MB
      maxFiles: 10,
    }),
    
    // Lab activity log
    new winston.transports.File({
      filename: path.join(logDir, 'lab-activity.log'),
      level: 'info',
      maxsize: 5242880, // 5MB
      maxFiles: 5,
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      )
    }),
  ],
  
  // Handle uncaught exceptions
  exceptionHandlers: [
    new winston.transports.File({
      filename: path.join(logDir, 'exceptions.log')
    })
  ],
  
  // Handle unhandled rejections
  rejectionHandlers: [
    new winston.transports.File({
      filename: path.join(logDir, 'rejections.log')
    })
  ]
});

// Add console transport for development
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: consoleFormat
  }));
}

// Custom methods for specific logging scenarios
logger.labActivity = function(action, labId, userId, details = {}) {
  this.info('Lab Activity', {
    action,
    labId,
    userId,
    details,
    category: 'lab_activity',
    timestamp: new Date().toISOString()
  });
};

logger.flagSubmission = function(userId, flag, labId, success, details = {}) {
  this.info('Flag Submission', {
    userId,
    flag: success ? flag : 'REDACTED',
    labId,
    success,
    details,
    category: 'flag_submission',
    timestamp: new Date().toISOString()
  });
};

logger.vpnActivity = function(userId, action, details = {}) {
  this.info('VPN Activity', {
    userId,
    action,
    details,
    category: 'vpn_activity',
    timestamp: new Date().toISOString()
  });
};

logger.security = function(level, event, userId, details = {}) {
  this[level]('Security Event', {
    event,
    userId,
    details,
    category: 'security',
    severity: level,
    timestamp: new Date().toISOString()
  });
};

module.exports = logger;