const express = require('express');
const router = express.Router();

router.get('/config', async (req, res) => {
  res.json({
    success: true,
    vpn_config: {
      server: 'localhost',
      port: 1194,
      protocol: 'udp'
    }
  });
});

router.post('/certificate', async (req, res) => {
  res.json({
    success: true,
    message: 'VPN certificate generated',
    download_url: '/api/vpn/download/certificate'
  });
});

router.get('/status', async (req, res) => {
  res.json({
    success: true,
    status: 'connected',
    connected_users: 5,
    server_load: 0.3
  });
});

module.exports = router;