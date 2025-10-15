const Redis = require('ioredis');
const logger = require('../utils/logger');

let redisClient = null;

const connectRedis = async () => {
  try {
    const redisConfig = {
      host: process.env.REDIS_HOST || 'localhost',
      port: process.env.REDIS_PORT || 6379,
      password: process.env.REDIS_PASSWORD || undefined,
      db: process.env.REDIS_DB || 0,
      retryDelayOnFailover: 100,
      maxRetriesPerRequest: 3,
      lazyConnect: true,
    };

    redisClient = new Redis(redisConfig);

    // Event handlers
    redisClient.on('connect', () => {
      logger.info(`Redis connected to ${redisConfig.host}:${redisConfig.port}`);
    });

    redisClient.on('error', (err) => {
      logger.error('Redis connection error:', err);
    });

    redisClient.on('close', () => {
      logger.warn('Redis connection closed');
    });

    redisClient.on('reconnecting', () => {
      logger.info('Redis reconnecting...');
    });

    // Test connection
    await redisClient.ping();
    
    // Store client globally for access in other modules
    global.redisClient = redisClient;
    
    return redisClient;
  } catch (error) {
    logger.error('Redis connection failed:', error);
    throw error;
  }
};

const getRedisClient = () => {
  if (!redisClient) {
    throw new Error('Redis client not initialized');
  }
  return redisClient;
};

// Utility functions for common Redis operations
const cache = {
  async get(key) {
    try {
      const client = getRedisClient();
      const value = await client.get(key);
      return value ? JSON.parse(value) : null;
    } catch (error) {
      logger.error('Redis get error:', error);
      return null;
    }
  },

  async set(key, value, ttl = 3600) {
    try {
      const client = getRedisClient();
      const serialized = JSON.stringify(value);
      await client.setex(key, ttl, serialized);
      return true;
    } catch (error) {
      logger.error('Redis set error:', error);
      return false;
    }
  },

  async del(key) {
    try {
      const client = getRedisClient();
      await client.del(key);
      return true;
    } catch (error) {
      logger.error('Redis delete error:', error);
      return false;
    }
  },

  async exists(key) {
    try {
      const client = getRedisClient();
      const exists = await client.exists(key);
      return exists === 1;
    } catch (error) {
      logger.error('Redis exists error:', error);
      return false;
    }
  },

  async setHash(key, field, value) {
    try {
      const client = getRedisClient();
      await client.hset(key, field, JSON.stringify(value));
      return true;
    } catch (error) {
      logger.error('Redis hset error:', error);
      return false;
    }
  },

  async getHash(key, field) {
    try {
      const client = getRedisClient();
      const value = await client.hget(key, field);
      return value ? JSON.parse(value) : null;
    } catch (error) {
      logger.error('Redis hget error:', error);
      return null;
    }
  }
};

module.exports = { connectRedis, getRedisClient, cache };