const Docker = require('dockerode');
const logger = require('./logger');

class DockerManager {
  constructor() {
    this.docker = new Docker();
    this.runningLabs = new Map();
  }

  async initialize() {
    try {
      // Test Docker connection
      const info = await this.docker.info();
      logger.info(`Docker initialized - Version: ${info.ServerVersion}`);
      return true;
    } catch (error) {
      logger.error('Failed to initialize Docker:', error);
      throw error;
    }
  }

  async startLab(labId, userId, labConfig) {
    try {
      const containerName = `oswa-${labId}-${userId}`;
      
      // Check if container already exists
      if (this.runningLabs.has(containerName)) {
        logger.warn(`Lab ${labId} already running for user ${userId}`);
        return this.runningLabs.get(containerName);
      }

      // Create and start container
      const container = await this.docker.createContainer({
        Image: labConfig.image,
        name: containerName,
        ExposedPorts: labConfig.ports || {},
        HostConfig: {
          PortBindings: labConfig.portBindings || {},
          AutoRemove: true
        },
        Env: labConfig.env || []
      });

      await container.start();
      
      // Store running lab info
      const labInfo = {
        containerId: container.id,
        containerName,
        labId,
        userId,
        startTime: new Date(),
        ports: labConfig.portBindings
      };
      
      this.runningLabs.set(containerName, labInfo);
      
      logger.info(`Lab ${labId} started for user ${userId} - Container: ${containerName}`);
      return labInfo;
    } catch (error) {
      logger.error(`Failed to start lab ${labId}:`, error);
      throw error;
    }
  }

  async stopLab(labId, userId) {
    try {
      const containerName = `oswa-${labId}-${userId}`;
      
      if (!this.runningLabs.has(containerName)) {
        logger.warn(`Lab ${labId} not running for user ${userId}`);
        return false;
      }

      const labInfo = this.runningLabs.get(containerName);
      const container = this.docker.getContainer(labInfo.containerId);
      
      await container.stop();
      await container.remove();
      
      this.runningLabs.delete(containerName);
      
      logger.info(`Lab ${labId} stopped for user ${userId}`);
      return true;
    } catch (error) {
      logger.error(`Failed to stop lab ${labId}:`, error);
      throw error;
    }
  }

  async getLabStatus(labId, userId) {
    const containerName = `oswa-${labId}-${userId}`;
    return this.runningLabs.get(containerName) || null;
  }

  async stopAllLabs() {
    try {
      const promises = [];
      for (const [containerName, labInfo] of this.runningLabs) {
        promises.push(this.stopLab(labInfo.labId, labInfo.userId));
      }
      await Promise.all(promises);
      logger.info('All labs stopped successfully');
    } catch (error) {
      logger.error('Error stopping labs:', error);
      throw error;
    }
  }

  getRunningLabs() {
    return Array.from(this.runningLabs.values());
  }
}

module.exports = new DockerManager();