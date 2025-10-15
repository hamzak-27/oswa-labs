const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const Flag = require('../models/Flag');
const LabProgress = require('../models/LabProgress');
const User = require('../models/User');
const logger = require('../utils/logger');
const authMiddleware = require('../middleware/auth');

// Rate limiting for flag submissions
const flagSubmissionLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 attempts per minute
  message: 'Too many flag submission attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Known flags for different labs
const VALID_FLAGS = {
  'xss-lab': [
    'FLAG{R3FL3CT3D_XSS_M4ST3R}',
    'FLAG{ST0R3D_XSS_C00K13_TH13F}',
    'FLAG{D0M_XSS_CSP_BYP4SS_L33T}'
  ],
  'jwt-attacks-lab': [
    'FLAG{JWT_N0N3_4LG0R1THM_BYP4SS}',
    'FLAG{JWT_W34K_S3CR3T_CR4CK3D}',
    'FLAG{JWT_4LG0R1THM_C0NFUS10N_H4CK}',
    'FLAG{JWT_1NJ3CT10N_V1A_K1D_CL41M}',
    'FLAG{JWT_ADMIN_PRIVILEGE_ESCALATION}'
  ]
};

// Flag difficulty and points mapping
const FLAG_METADATA = {
  'FLAG{R3FL3CT3D_XSS_M4ST3R}': { difficulty: 'easy', points: 100, category: 'xss', type: 'reflected' },
  'FLAG{ST0R3D_XSS_C00K13_TH13F}': { difficulty: 'medium', points: 250, category: 'xss', type: 'stored' },
  'FLAG{D0M_XSS_CSP_BYP4SS_L33T}': { difficulty: 'hard', points: 500, category: 'xss', type: 'dom' },
  'FLAG{JWT_N0N3_4LG0R1THM_BYP4SS}': { difficulty: 'easy', points: 100, category: 'jwt', type: 'none_algorithm' },
  'FLAG{JWT_W34K_S3CR3T_CR4CK3D}': { difficulty: 'medium', points: 250, category: 'jwt', type: 'weak_secret' },
  'FLAG{JWT_4LG0R1THM_C0NFUS10N_H4CK}': { difficulty: 'hard', points: 500, category: 'jwt', type: 'algorithm_confusion' },
  'FLAG{JWT_1NJ3CT10N_V1A_K1D_CL41M}': { difficulty: 'hard', points: 400, category: 'jwt', type: 'kid_injection' },
  'FLAG{JWT_ADMIN_PRIVILEGE_ESCALATION}': { difficulty: 'medium', points: 300, category: 'jwt', type: 'privilege_escalation' }
};

// POST /api/flags/submit - Submit a captured flag
router.post('/submit', 
  flagSubmissionLimiter,
  authMiddleware,
  [
    body('flag')
      .notEmpty()
      .withMessage('Flag is required')
      .matches(/^FLAG\{[A-Z0-9_]+\}$/)
      .withMessage('Flag must be in format FLAG{...}'),
    body('labId')
      .notEmpty()
      .withMessage('Lab ID is required')
      .isIn(['xss-lab', 'jwt-attacks-lab'])
      .withMessage('Invalid lab ID'),
    body('notes')
      .optional()
      .isLength({ max: 500 })
      .withMessage('Notes must be less than 500 characters')
  ],
  async (req, res) => {
    try {
      // Validate request
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          error: 'Validation failed',
          details: errors.array()
        });
      }

      const { flag, labId, notes } = req.body;
      const userId = req.user.id;

      // Check if flag is valid
      const isValidFlag = VALID_FLAGS[labId] && VALID_FLAGS[labId].includes(flag);
      
      if (!isValidFlag) {
        logger.flagSubmission(userId, flag, labId, false, { reason: 'invalid_flag' });
        
        return res.status(400).json({
          success: false,
          error: 'Invalid flag',
          hint: 'Make sure you have the correct flag format and it belongs to the specified lab'
        });
      }

      // Check if user has already submitted this flag
      const existingSubmission = await Flag.findOne({
        userId,
        flag,
        labId
      });

      if (existingSubmission) {
        return res.status(400).json({
          success: false,
          error: 'Flag already submitted',
          previousSubmission: {
            submittedAt: existingSubmission.submittedAt,
            points: existingSubmission.points
          }
        });
      }

      // Get flag metadata
      const flagMeta = FLAG_METADATA[flag];

      // Create flag submission record
      const flagSubmission = new Flag({
        userId,
        username: req.user.username,
        flag,
        labId,
        category: flagMeta.category,
        difficulty: flagMeta.difficulty,
        points: flagMeta.points,
        type: flagMeta.type,
        notes: notes || '',
        submittedAt: new Date(),
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });

      await flagSubmission.save();

      // Update user's lab progress
      let progress = await LabProgress.findOne({ userId, labId });
      
      if (!progress) {
        progress = new LabProgress({
          userId,
          labId,
          status: 'in_progress',
          startedAt: new Date(),
          flagsSubmitted: [],
          totalPoints: 0
        });
      }

      progress.flagsSubmitted.push({
        flag,
        submittedAt: new Date(),
        points: flagMeta.points,
        difficulty: flagMeta.difficulty,
        type: flagMeta.type
      });

      progress.totalPoints += flagMeta.points;
      progress.lastActivity = new Date();

      // Check if lab is completed (all flags found)
      const totalFlags = VALID_FLAGS[labId].length;
      const submittedFlags = progress.flagsSubmitted.length;
      
      if (submittedFlags >= totalFlags) {
        progress.status = 'completed';
        progress.completedAt = new Date();
      }

      await progress.save();

      // Update user's total points
      await User.findByIdAndUpdate(userId, {
        $inc: { 'stats.totalPoints': flagMeta.points, 'stats.flagsSubmitted': 1 }
      });

      // Log successful submission
      logger.flagSubmission(userId, flag, labId, true, {
        points: flagMeta.points,
        difficulty: flagMeta.difficulty,
        type: flagMeta.type,
        totalPoints: progress.totalPoints
      });

      res.json({
        success: true,
        message: '🎯 Flag captured successfully!',
        flagDetails: {
          flag,
          points: flagMeta.points,
          difficulty: flagMeta.difficulty,
          category: flagMeta.category,
          type: flagMeta.type
        },
        progress: {
          labId,
          flagsSubmitted: progress.flagsSubmitted.length,
          totalFlags,
          totalPoints: progress.totalPoints,
          status: progress.status,
          completionPercentage: Math.round((progress.flagsSubmitted.length / totalFlags) * 100)
        },
        achievements: submittedFlags >= totalFlags ? ['Lab Completed!'] : []
      });

    } catch (error) {
      logger.error('Flag submission error:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to submit flag',
        details: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
);

// GET /api/flags/history - Get user's flag submission history
router.get('/history', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { labId, limit = 50, offset = 0 } = req.query;

    const query = { userId };
    if (labId) {
      query.labId = labId;
    }

    const flags = await Flag.find(query)
      .sort({ submittedAt: -1 })
      .limit(parseInt(limit))
      .skip(parseInt(offset))
      .select('-__v');

    const total = await Flag.countDocuments(query);

    // Group by lab for summary
    const summary = await Flag.aggregate([
      { $match: { userId: req.user._id } },
      {
        $group: {
          _id: '$labId',
          totalFlags: { $sum: 1 },
          totalPoints: { $sum: '$points' },
          difficulties: { $push: '$difficulty' },
          categories: { $push: '$category' }
        }
      }
    ]);

    res.json({
      success: true,
      flags,
      pagination: {
        total,
        limit: parseInt(limit),
        offset: parseInt(offset),
        hasMore: total > (parseInt(offset) + parseInt(limit))
      },
      summary
    });

  } catch (error) {
    logger.error('Flag history error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve flag history'
    });
  }
});

// GET /api/flags/leaderboard - Get flag submission leaderboard
router.get('/leaderboard', async (req, res) => {
  try {
    const { labId, timeframe = 'all' } = req.query;
    
    let matchStage = {};
    
    // Filter by lab if specified
    if (labId) {
      matchStage.labId = labId;
    }

    // Filter by timeframe
    if (timeframe !== 'all') {
      const now = new Date();
      let startDate;
      
      switch (timeframe) {
        case 'day':
          startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
          break;
        case 'week':
          startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
          break;
        case 'month':
          startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
          break;
      }
      
      if (startDate) {
        matchStage.submittedAt = { $gte: startDate };
      }
    }

    const leaderboard = await Flag.aggregate([
      { $match: matchStage },
      {
        $group: {
          _id: '$userId',
          username: { $first: '$username' },
          totalPoints: { $sum: '$points' },
          flagsCount: { $sum: 1 },
          labs: { $addToSet: '$labId' },
          lastSubmission: { $max: '$submittedAt' },
          difficulties: { $push: '$difficulty' }
        }
      },
      {
        $addFields: {
          labsCompleted: { $size: '$labs' },
          easyFlags: { $size: { $filter: { input: '$difficulties', cond: { $eq: ['$$this', 'easy'] } } } },
          mediumFlags: { $size: { $filter: { input: '$difficulties', cond: { $eq: ['$$this', 'medium'] } } } },
          hardFlags: { $size: { $filter: { input: '$difficulties', cond: { $eq: ['$$this', 'hard'] } } } }
        }
      },
      { $sort: { totalPoints: -1, lastSubmission: -1 } },
      { $limit: 50 }
    ]);

    // Add ranking
    const rankedLeaderboard = leaderboard.map((entry, index) => ({
      rank: index + 1,
      ...entry
    }));

    res.json({
      success: true,
      leaderboard: rankedLeaderboard,
      metadata: {
        timeframe,
        labId: labId || 'all',
        totalUsers: rankedLeaderboard.length,
        generatedAt: new Date().toISOString()
      }
    });

  } catch (error) {
    logger.error('Leaderboard error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve leaderboard'
    });
  }
});

// GET /api/flags/stats - Get flag statistics
router.get('/stats', async (req, res) => {
  try {
    const stats = await Promise.all([
      // Total flags submitted
      Flag.countDocuments(),
      
      // Flags by lab
      Flag.aggregate([
        { $group: { _id: '$labId', count: { $sum: 1 } } }
      ]),
      
      // Flags by difficulty
      Flag.aggregate([
        { $group: { _id: '$difficulty', count: { $sum: 1 } } }
      ]),
      
      // Most recent submissions
      Flag.find().sort({ submittedAt: -1 }).limit(10).select('flag labId username submittedAt points'),
      
      // Top performers
      Flag.aggregate([
        { $group: { _id: '$userId', username: { $first: '$username' }, totalPoints: { $sum: '$points' } } },
        { $sort: { totalPoints: -1 } },
        { $limit: 5 }
      ])
    ]);

    res.json({
      success: true,
      stats: {
        totalSubmissions: stats[0],
        byLab: stats[1],
        byDifficulty: stats[2],
        recentSubmissions: stats[3],
        topPerformers: stats[4]
      }
    });

  } catch (error) {
    logger.error('Flag stats error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve flag statistics'
    });
  }
});

// GET /api/flags/validate/:flag - Validate a flag (without submitting)
router.get('/validate/:flag', authMiddleware, async (req, res) => {
  try {
    const { flag } = req.params;
    const { labId } = req.query;

    if (!labId || !VALID_FLAGS[labId]) {
      return res.status(400).json({
        success: false,
        error: 'Lab ID is required and must be valid'
      });
    }

    const isValid = VALID_FLAGS[labId].includes(flag);
    const metadata = isValid ? FLAG_METADATA[flag] : null;

    res.json({
      success: true,
      isValid,
      flag,
      labId,
      ...(metadata && {
        metadata: {
          difficulty: metadata.difficulty,
          points: metadata.points,
          category: metadata.category,
          type: metadata.type
        }
      })
    });

  } catch (error) {
    logger.error('Flag validation error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to validate flag'
    });
  }
});

module.exports = router;