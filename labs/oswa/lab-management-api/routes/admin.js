const express = require('express');
const router = express.Router();

router.get('/dashboard', async (req, res) => {
  res.json({
    success: true,
    dashboard: {
      total_users: 100,
      active_labs: 12,
      total_flags_submitted: 1234,
      system_health: 'good'
    }
  });
});

router.get('/users', async (req, res) => {
  res.json({
    success: true,
    users: [],
    total: 0
  });
});

module.exports = router;