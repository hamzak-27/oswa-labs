const express = require('express');
const router = express.Router();

router.get('/', async (req, res) => {
  res.json({
    success: true,
    progress: {
      total_flags: 9,
      captured_flags: 3,
      completion_percentage: 33,
      labs_completed: 0,
      labs_in_progress: 2,
      time_spent: 7200000, // 2 hours in ms
      rank: 'Beginner',
      level: 1,
      points: 150
    }
  });
});

router.get('/stats', async (req, res) => {
  res.json({
    success: true,
    stats: {
      total_users: 100,
      total_submissions: 450,
      average_completion: 65,
      most_popular_lab: 'xss-lab'
    }
  });
});

module.exports = router;