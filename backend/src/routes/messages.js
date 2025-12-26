const express = require('express');
const Message = require('../models/message');
const { authMiddleware } = require('../middleware/auth');
const { audit } = require('../utils/audit');

const router = express.Router();

// Store encrypted message or handshake payload (ciphertext only).
router.post('/', authMiddleware, async (req, res) => {
  const { receiverId, ciphertext, iv, authTag, aad, seq, ts, type = 'text', nonce, metadata } =
    req.body || {};

  if (!receiverId || !ciphertext || !iv || !authTag || typeof seq !== 'number' || !ts) {
    return res.status(400).json({ error: 'missing_fields' });
  }

  try {
    const existing = await Message.findOne({ sender: req.user.id, receiver: receiverId, seq });
    if (existing) {
      await audit('replay.detected', req.user.id, { receiverId, seq });
      return res.status(409).json({ error: 'replay_detected' });
    }

    const message = await Message.create({
      sender: req.user.id,
      receiver: receiverId,
      ciphertext,
      iv,
      authTag,
      aad,
      seq,
      ts: new Date(ts),
      type,
      nonce,
      metadata,
    });
    await audit(type === 'handshake' ? 'handshake.store' : 'message.store', req.user.id, {
      receiverId,
      seq,
      type,
    });

    return res.status(201).json({ id: message._id });
  } catch (err) {
    console.error('store message failed', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

// Fetch inbox messages (ciphertext only)
router.get('/inbox', authMiddleware, async (req, res) => {
  const { type } = req.query;
  const filter = { receiver: req.user.id };
  if (type) filter.type = type;

  try {
    const messages = await Message.find(filter)
      .sort({ ts: 1 })
      .limit(200)
      .select('-__v');
    await audit('metadata.access', req.user.id, { count: messages.length, filter: type || 'all' });
    return res.json({ messages });
  } catch (err) {
    return res.status(500).json({ error: 'server_error' });
  }
});

// Fetch conversation thread
router.get('/thread/:peerId', authMiddleware, async (req, res) => {
  try {
    const messages = await Message.find({
      $or: [
        { sender: req.user.id, receiver: req.params.peerId },
        { sender: req.params.peerId, receiver: req.user.id },
      ],
    })
      .sort({ ts: 1 })
      .limit(400)
      .select('-__v');
    await audit('metadata.access', req.user.id, { peerId: req.params.peerId, count: messages.length });
    return res.json({ messages });
  } catch (err) {
    return res.status(500).json({ error: 'server_error' });
  }
});

module.exports = router;
