const express = require('express');
const app = express();
const PORT = 8000;

app.use(express.json());

app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    service: 'OSWA Lab Management API',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

app.get('/test', (req, res) => {
  res.json({ message: 'Test endpoint working!' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Test API running on port ${PORT}`);
  console.log(`❤️  Health Check: http://localhost:${PORT}/health`);
});