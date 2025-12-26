const express = require('express');
const { authMiddleware } = require('../middleware/auth');
const { audit } = require('../utils/audit');

const router = express.Router();

// Allow clients to report security-relevant events (e.g., decrypt failures, invalid signatures).
router.post('/client', authMiddleware, async (req, res) => {
  const { event, details } = req.body || {};
  const allowed = new Set(['decrypt.fail', 'decrypt.fail.file', 'signature.invalid', 'handshake.error']);
  if (!event || !allowed.has(event)) {
    return res.status(400).json({ error: 'invalid_event' });
  }
  try {
    await audit(event, req.user.id, details || {});
    return res.status(201).json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: 'server_error' });
  }
});

module.exports = router;
