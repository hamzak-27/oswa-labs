const express = require('express');
const axios = require('axios');

function createLabProxy(targetUrl) {
  const router = express.Router();
  
  router.all('/*', async (req, res) => {
    try {
      const response = await axios({
        method: req.method,
        url: `${targetUrl}${req.originalUrl.replace('/api/proxy/' + req.originalUrl.split('/')[3], '')}`,
        data: req.body,
        headers: {
          ...req.headers,
          host: undefined
        },
        timeout: 30000
      });
      
      res.status(response.status).json(response.data);
    } catch (error) {
      if (error.code === 'ECONNREFUSED') {
        res.status(503).json({
          success: false,
          message: 'Lab service unavailable',
          error: 'Connection refused'
        });
      } else {
        res.status(error.response?.status || 500).json({
          success: false,
          message: 'Proxy error',
          error: error.message
        });
      }
    }
  });
  
  return router;
}

module.exports = createLabProxy;