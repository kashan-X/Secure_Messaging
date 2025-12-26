const fs = require('fs');
const path = require('path');

// Load environment variables if .env exists
const envPath = path.join(__dirname, '..', '.env');
if (fs.existsSync(envPath)) {
  // Lazy require to avoid dependency issues if .env is missing
  require('dotenv').config({ path: envPath });
}

const origins =
  process.env.CLIENT_ORIGINS ||
  process.env.CLIENT_ORIGIN ||
  'http://localhost:5173,http://127.0.0.1:5173';

module.exports = {
  PORT: process.env.PORT || 4000,
  MONGO_URI: process.env.MONGO_URI || 'mongodb://localhost:27017/e2ee',
  JWT_SECRET: process.env.JWT_SECRET || 'change-me-in-production',
  TOKEN_TTL: process.env.TOKEN_TTL || '1h',
  CLIENT_ORIGINS: origins.split(',').map((o) => o.trim()).filter(Boolean),
  MAX_JSON_SIZE: process.env.MAX_JSON_SIZE || '10mb',
};
