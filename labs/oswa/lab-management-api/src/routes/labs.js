const express = require('express');
const { exec } = require('child_process');
const Docker = require('dockerode');
const router = express.Router();

const docker = new Docker();

// Lab configurations with VPN network settings
const LAB_CONFIGS = {
  'xss-lab': {
    name: 'XSS Attacks Lab',
    composeFile: 'xss-lab/docker-compose.yml',
    services: ['xss-mongodb', 'xss-backend', 'xss-frontend'],
    vpnIP: '172.20.1.10',
    vpnPort: 3000,
    frontendUrl: 'http://localhost:3000',
    category: 'Web Security',
    difficulty: 'medium',
    totalFlags: 3,
    description: 'Learn Cross-Site Scripting vulnerabilities including reflected, stored, and DOM-based XSS.'
  },
  'jwt-attacks-lab': {
    name: 'JWT Attacks Lab',
    composeFile: 'jwt-attacks-lab/docker-compose.yml',
    services: ['jwt-mongodb', 'jwt-backend', 'jwt-frontend'],
    vpnIP: '172.20.2.10',
    vpnPort: 3000,
    frontendUrl: 'http://localhost:3001',
    category: 'Authentication',
    difficulty: 'hard',
    totalFlags: 4,
    description: 'Master JWT security flaws including none algorithm, weak secrets, and algorithm confusion.'
  },
  'sql-injection-lab': {
    name: 'SQL Injection Lab',
    composeFile: 'sql-injection-lab/docker-compose.yml',
    services: ['sql-mysql', 'sql-webapp'],
    vpnIP: '172.20.3.10',
    vpnPort: 80,
    frontendUrl: 'http://localhost:61505',
    category: 'Database Security',
    difficulty: 'hard',
    totalFlags: 5,
    description: 'Master SQL injection techniques including authentication bypass, blind injection, and data extraction.'
  }
};

/**
 * GET /api/labs
 * Get all available labs and their status
 */
router.get('/', async (req, res) => {
  try {
    const labs = [];
    
    for (const [labId, config] of Object.entries(LAB_CONFIGS)) {
      const status = await getLabStatus(labId);
      const userProgress = await getUserLabProgress(req.user?.id, labId);
      
      labs.push({
        id: labId,
        name: config.name,
        status: status,
        url: status === 'running' ? config.frontendUrl : undefined,
        vpnIP: status === 'running' ? config.vpnIP : undefined,
        vpnPort: status === 'running' ? config.vpnPort : undefined,
        flags: userProgress.flagsCaptured,
        totalFlags: config.totalFlags,
        difficulty: config.difficulty,
        description: config.description,
        category: config.category,
        lastStarted: status === 'running' ? await getLabStartTime(labId) : null
      });
    }
    
    res.json(labs);
    
  } catch (error) {
    console.error('Error fetching labs:', error);
    res.status(500).json({ error: 'Failed to fetch lab status' });
  }
});

/**
 * GET /api/labs/:labId
 * Get specific lab information
 */
router.get('/:labId', async (req, res) => {
  try {
    const { labId } = req.params;
    const config = LAB_CONFIGS[labId];
    
    if (!config) {
      return res.status(404).json({ error: 'Lab not found' });
    }
    
    const status = await getLabStatus(labId);
    const userProgress = await getUserLabProgress(req.user?.id, labId);
    const containers = await getLabContainers(labId);
    
    res.json({
      id: labId,
      name: config.name,
      status: status,
      url: status === 'running' ? config.frontendUrl : undefined,
      vpnIP: status === 'running' ? config.vpnIP : undefined,
      vpnPort: status === 'running' ? config.vpnPort : undefined,
      flags: userProgress.flagsCaptured,
      totalFlags: config.totalFlags,
      difficulty: config.difficulty,
      description: config.description,
      category: config.category,
      containers: containers,
      lastStarted: status === 'running' ? await getLabStartTime(labId) : null,
      logs: status === 'running' ? await getLabLogs(labId) : []
    });
    
  } catch (error) {
    console.error(`Error fetching lab ${req.params.labId}:`, error);
    res.status(500).json({ error: 'Failed to fetch lab information' });
  }
});

/**
 * POST /api/labs/:labId/start
 * Start a specific lab
 */
router.post('/:labId/start', async (req, res) => {
  try {
    const { labId } = req.params;
    const config = LAB_CONFIGS[labId];
    
    if (!config) {
      return res.status(404).json({ error: 'Lab not found' });
    }
    
    const currentStatus = await getLabStatus(labId);
    if (currentStatus === 'running') {
      return res.json({ 
        success: true, 
        message: 'Lab is already running',
        status: 'running',
        vpnIP: config.vpnIP,
        vpnPort: config.vpnPort
      });
    }
    
    console.log(`🚀 Starting lab: ${labId}`);
    
    // Start the lab using Docker Compose
    await startLabContainers(labId);
    
    // Wait for services to be ready
    await waitForLabServices(labId);
    
    // Log lab start event
    await logLabEvent(req.user?.id, labId, 'started');
    
    res.json({
      success: true,
      message: `${config.name} started successfully`,
      status: 'running',
      vpnIP: config.vpnIP,
      vpnPort: config.vpnPort,
      url: config.frontendUrl,
      startedAt: new Date().toISOString()
    });
    
  } catch (error) {
    console.error(`Error starting lab ${req.params.labId}:`, error);
    res.status(500).json({ 
      error: 'Failed to start lab',
      message: error.message 
    });
  }
});

/**
 * POST /api/labs/:labId/stop
 * Stop a specific lab
 */
router.post('/:labId/stop', async (req, res) => {
  try {
    const { labId } = req.params;
    const config = LAB_CONFIGS[labId];
    
    if (!config) {
      return res.status(404).json({ error: 'Lab not found' });
    }
    
    const currentStatus = await getLabStatus(labId);
    if (currentStatus === 'stopped') {
      return res.json({ 
        success: true, 
        message: 'Lab is already stopped',
        status: 'stopped'
      });
    }
    
    console.log(`🛑 Stopping lab: ${labId}`);
    
    // Stop the lab using Docker Compose
    await stopLabContainers(labId);
    
    // Log lab stop event
    await logLabEvent(req.user?.id, labId, 'stopped');
    
    res.json({
      success: true,
      message: `${config.name} stopped successfully`,
      status: 'stopped',
      stoppedAt: new Date().toISOString()
    });
    
  } catch (error) {
    console.error(`Error stopping lab ${req.params.labId}:`, error);
    res.status(500).json({ 
      error: 'Failed to stop lab',
      message: error.message 
    });
  }
});

/**
 * POST /api/labs/:labId/restart
 * Restart a specific lab
 */
router.post('/:labId/restart', async (req, res) => {
  try {
    const { labId } = req.params;
    const config = LAB_CONFIGS[labId];
    
    if (!config) {
      return res.status(404).json({ error: 'Lab not found' });
    }
    
    console.log(`🔄 Restarting lab: ${labId}`);
    
    // Stop first
    await stopLabContainers(labId);
    
    // Wait a moment
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Start again
    await startLabContainers(labId);
    await waitForLabServices(labId);
    
    // Log restart event
    await logLabEvent(req.user?.id, labId, 'restarted');
    
    res.json({
      success: true,
      message: `${config.name} restarted successfully`,
      status: 'running',
      vpnIP: config.vpnIP,
      vpnPort: config.vpnPort,
      url: config.frontendUrl,
      restartedAt: new Date().toISOString()
    });
    
  } catch (error) {
    console.error(`Error restarting lab ${req.params.labId}:`, error);
    res.status(500).json({ 
      error: 'Failed to restart lab',
      message: error.message 
    });
  }
});

/**
 * GET /api/labs/:labId/logs
 * Get lab container logs
 */
router.get('/:labId/logs', async (req, res) => {
  try {
    const { labId } = req.params;
    const config = LAB_CONFIGS[labId];
    
    if (!config) {
      return res.status(404).json({ error: 'Lab not found' });
    }
    
    const logs = await getLabLogs(labId);
    res.json({ logs });
    
  } catch (error) {
    console.error(`Error fetching logs for lab ${req.params.labId}:`, error);
    res.status(500).json({ error: 'Failed to fetch lab logs' });
  }
});

// Helper Functions

async function getLabStatus(labId) {
  try {
    const config = LAB_CONFIGS[labId];
    if (!config) return 'unknown';
    
    // Check if lab containers are running
    const containers = await docker.listContainers();
    const labContainers = containers.filter(container => 
      container.Names.some(name => 
        config.services.some(service => name.includes(service))
      )
    );
    
    if (labContainers.length === 0) {
      return 'stopped';
    }
    
    const runningCount = labContainers.filter(c => c.State === 'running').length;
    const totalRequired = config.services.length;
    
    if (runningCount === totalRequired) {
      return 'running';
    } else if (runningCount > 0) {
      return 'starting';
    } else {
      return 'stopped';
    }
    
  } catch (error) {
    console.error(`Error checking status for lab ${labId}:`, error);
    return 'unknown';
  }
}

async function startLabContainers(labId) {
  return new Promise((resolve, reject) => {
    const config = LAB_CONFIGS[labId];
    const command = `docker-compose -f docker-compose.platform.yml up -d ${config.services.join(' ')}`;
    
    exec(command, (error, stdout, stderr) => {
      if (error) {
        console.error(`Failed to start ${labId}:`, error);
        reject(error);
        return;
      }
      
      console.log(`✅ Started ${labId} containers:`, stdout);
      resolve(stdout);
    });
  });
}

async function stopLabContainers(labId) {
  return new Promise((resolve, reject) => {
    const config = LAB_CONFIGS[labId];
    const command = `docker-compose -f docker-compose.platform.yml stop ${config.services.join(' ')}`;
    
    exec(command, (error, stdout, stderr) => {
      if (error) {
        console.error(`Failed to stop ${labId}:`, error);
        reject(error);
        return;
      }
      
      console.log(`🛑 Stopped ${labId} containers:`, stdout);
      resolve(stdout);
    });
  });
}

async function waitForLabServices(labId) {
  const config = LAB_CONFIGS[labId];
  console.log(`⏳ Waiting for ${labId} services to be ready...`);
  
  // Wait for containers to be healthy/ready
  let retries = 30;
  while (retries > 0) {
    const status = await getLabStatus(labId);
    if (status === 'running') {
      console.log(`✅ ${labId} services are ready`);
      return;
    }
    
    await new Promise(resolve => setTimeout(resolve, 2000));
    retries--;
  }
  
  throw new Error(`${labId} services failed to start within timeout`);
}

async function getLabContainers(labId) {
  try {
    const config = LAB_CONFIGS[labId];
    const containers = await docker.listContainers({ all: true });
    
    return containers
      .filter(container => 
        container.Names.some(name => 
          config.services.some(service => name.includes(service))
        )
      )
      .map(container => ({
        id: container.Id,
        name: container.Names[0].replace('/', ''),
        state: container.State,
        status: container.Status,
        ports: container.Ports,
        created: container.Created
      }));
      
  } catch (error) {
    console.error(`Error fetching containers for lab ${labId}:`, error);
    return [];
  }
}

async function getLabLogs(labId) {
  try {
    const containers = await getLabContainers(labId);
    const logs = [];
    
    for (const container of containers) {
      try {
        const dockerContainer = docker.getContainer(container.id);
        const logStream = await dockerContainer.logs({
          stdout: true,
          stderr: true,
          tail: 100,
          timestamps: true
        });
        
        logs.push({
          containerName: container.name,
          logs: logStream.toString()
        });
        
      } catch (logError) {
        console.error(`Error fetching logs for container ${container.name}:`, logError);
      }
    }
    
    return logs;
    
  } catch (error) {
    console.error(`Error fetching logs for lab ${labId}:`, error);
    return [];
  }
}

async function getUserLabProgress(userId, labId) {
  // This would fetch from your database
  // For now, return mock data
  return {
    flagsCaptured: 0,
    lastAccessed: null,
    totalTime: 0
  };
}

async function getLabStartTime(labId) {
  try {
    const containers = await getLabContainers(labId);
    if (containers.length > 0) {
      return new Date(containers[0].created * 1000).toISOString();
    }
    return null;
  } catch (error) {
    return null;
  }
}

async function logLabEvent(userId, labId, event) {
  console.log(`📝 Lab Event: User ${userId} ${event} lab ${labId}`);
  // This would log to your database
}

module.exports = router;