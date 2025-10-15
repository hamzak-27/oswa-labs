const express = require('express');
const router = express.Router();

router.get('/', async (req, res) => {
  res.json({ success: true, deployments: [], total: 0 });
});

router.post('/', async (req, res) => {
  res.json({ success: true, message: 'Deployment created' });
});

module.exports = router;