const express = require('express');
const router = express.Router();
const dockerManager = require('../utils/dockerManager');

const AVAILABLE_LABS = {
  'xss-lab': {
    id: 'xss-lab',
    name: 'Cross-Site Scripting Lab',
    description: 'Learn XSS vulnerabilities including reflected, stored, and DOM-based XSS',
    image: 'oswa/xss-lab:latest',
    ports: {
      '3000/tcp': {}
    },
    portBindings: {
      '3000/tcp': [{ 'HostPort': '5000' }]
    },
    env: ['NODE_ENV=development'],
    difficulty: 'intermediate',
    flags_count: 5,
    estimated_time: '2-3 hours',
    categories: ['web', 'xss', 'client-side'],
    url: 'http://localhost:5000'
  },
  'jwt-attacks-lab': {
    id: 'jwt-attacks-lab',
    name: 'JWT Attacks Lab',
    description: 'Explore JWT vulnerabilities including weak secrets, algorithm confusion, and bypasses',
    image: 'oswa/jwt-lab:latest',
    ports: {
      '3000/tcp': {}
    },
    portBindings: {
      '3000/tcp': [{ 'HostPort': '5001' }]
    },
    env: ['NODE_ENV=development'],
    difficulty: 'intermediate',
    flags_count: 4,
    estimated_time: '1-2 hours',
    categories: ['web', 'jwt', 'authentication'],
    url: 'http://localhost:5001'
  }
};

// Get all available labs
router.get('/', async (req, res) => {
  try {
    const labs = Object.values(AVAILABLE_LABS).map(lab => ({
      id: lab.id,
      name: lab.name,
      description: lab.description,
      difficulty: lab.difficulty,
      flags_count: lab.flags_count,
      estimated_time: lab.estimated_time,
      categories: lab.categories
    }));
    
    res.json({
      success: true,
      labs,
      total: labs.length
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to fetch labs',
      error: error.message
    });
  }
});

// Get specific lab details
router.get('/:id', async (req, res) => {
  try {
    const lab = AVAILABLE_LABS[req.params.id];
    
    if (!lab) {
      return res.status(404).json({
        success: false,
        message: 'Lab not found'
      });
    }
    
    res.json({
      success: true,
      lab
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to fetch lab details',
      error: error.message
    });
  }
});

// Start a lab instance
router.post('/:id/start', async (req, res) => {
  try {
    const labId = req.params.id;
    const userId = req.body.userId || '1'; // Mock user ID
    
    const labConfig = AVAILABLE_LABS[labId];
    if (!labConfig) {
      return res.status(404).json({
        success: false,
        message: 'Lab not found'
      });
    }
    
    const labInfo = await dockerManager.startLab(labId, userId, labConfig);
    
    res.json({
      success: true,
      message: `Lab ${labId} started successfully`,
      lab: {
        ...labInfo,
        url: labConfig.url,
        access_time: new Date(),
        expires_at: new Date(Date.now() + 3 * 60 * 60 * 1000) // 3 hours
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: `Failed to start lab ${req.params.id}`,
      error: error.message
    });
  }
});

// Stop a lab instance
router.post('/:id/stop', async (req, res) => {
  try {
    const labId = req.params.id;
    const userId = req.body.userId || '1'; // Mock user ID
    
    const stopped = await dockerManager.stopLab(labId, userId);
    
    if (stopped) {
      res.json({
        success: true,
        message: `Lab ${labId} stopped successfully`
      });
    } else {
      res.status(404).json({
        success: false,
        message: 'Lab instance not found or already stopped'
      });
    }
  } catch (error) {
    res.status(500).json({
      success: false,
      message: `Failed to stop lab ${req.params.id}`,
      error: error.message
    });
  }
});

// Get lab status
router.get('/:id/status', async (req, res) => {
  try {
    const labId = req.params.id;
    const userId = req.query.userId || '1'; // Mock user ID
    
    const status = await dockerManager.getLabStatus(labId, userId);
    
    if (status) {
      const labConfig = AVAILABLE_LABS[labId];
      res.json({
        success: true,
        status: 'running',
        lab: {
          ...status,
          url: labConfig?.url,
          uptime: Date.now() - status.startTime.getTime()
        }
      });
    } else {
      res.json({
        success: true,
        status: 'stopped'
      });
    }
  } catch (error) {
    res.status(500).json({
      success: false,
      message: `Failed to get lab status for ${req.params.id}`,
      error: error.message
    });
  }
});

// Get all running labs
router.get('/instances/running', async (req, res) => {
  try {
    const runningLabs = dockerManager.getRunningLabs();
    
    res.json({
      success: true,
      running_labs: runningLabs.map(lab => ({
        labId: lab.labId,
        userId: lab.userId,
        containerName: lab.containerName,
        startTime: lab.startTime,
        uptime: Date.now() - lab.startTime.getTime()
      })),
      total: runningLabs.length
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to fetch running labs',
      error: error.message
    });
  }
});

module.exports = router;