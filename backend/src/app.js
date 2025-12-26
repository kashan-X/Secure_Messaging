const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const { CLIENT_ORIGINS, MAX_JSON_SIZE } = require('./config');




const mitmRoutes = require('./routes/mitm');
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const messageRoutes = require('./routes/messages');
const fileRoutes = require('./routes/files');
const logRoutes = require('./routes/logs');

const app = express();

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin || CLIENT_ORIGINS.includes(origin)) return cb(null, true);
      return cb(new Error('Not allowed by CORS'));
    },
    credentials: true,
  })
);
app.use(helmet());
app.use(express.json({ limit: MAX_JSON_SIZE }));
app.use(cookieParser());
app.use(morgan('tiny'));

app.get('/api/health', (_req, res) => res.json({ ok: true }));
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/messages', messageRoutes);
app.use('/api/files', fileRoutes);
app.use('/api/logs', logRoutes);
app.use('/api/mitm', mitmRoutes);

app.use((req, res) => res.status(404).json({ error: 'not_found' }));

module.exports = { app };
