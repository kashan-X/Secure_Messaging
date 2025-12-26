const express = require('express');
const { FileMeta, FileChunk } = require('../models/file');
const { authMiddleware } = require('../middleware/auth');
const { audit } = require('../utils/audit');

const router = express.Router();

// Initialize file transfer metadata (ciphertext-only upload follows).
router.post('/init', authMiddleware, async (req, res) => {
  const { fileId, receiverId, totalChunks, fileName, fileSize, mimeType } = req.body || {};
  if (!fileId || !receiverId || typeof totalChunks !== 'number') {
    return res.status(400).json({ error: 'missing_fields' });
  }

  try {
    const existing = await FileMeta.findOne({ fileId });
    if (existing) {
      return res.status(409).json({ error: 'file_exists' });
    }

    await FileMeta.create({
      fileId,
      receiver: receiverId,
      sender: req.user.id,
      totalChunks,
      fileName,
      fileSize,
      mimeType,
    });
    await audit('file.init', req.user.id, { receiverId, fileId, totalChunks });
    return res.status(201).json({ ok: true });
  } catch (err) {
    console.error('file init failed', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

// Store encrypted chunk
router.post('/:fileId/chunk', authMiddleware, async (req, res) => {
  const { fileId } = req.params;
  const { chunkIndex, ciphertext, iv, authTag, aad, receiverId } = req.body || {};
  if (!ciphertext || !iv || !authTag || typeof chunkIndex !== 'number' || !receiverId) {
    return res.status(400).json({ error: 'missing_fields' });
  }

  try {
    const meta = await FileMeta.findOne({ fileId });
    if (!meta) {
      return res.status(404).json({ error: 'file_not_found' });
    }

    if (String(meta.sender) !== req.user.id) {
      return res.status(403).json({ error: 'not_owner' });
    }

    const existing = await FileChunk.findOne({ fileId, chunkIndex });
    if (existing) {
      await audit('replay.detected', req.user.id, { fileId, chunkIndex });
      return res.status(409).json({ error: 'chunk_exists' });
    }

    await FileChunk.create({
      fileId,
      chunkIndex,
      ciphertext,
      iv,
      authTag,
      aad,
      sender: req.user.id,
      receiver: receiverId,
    });
    await audit('file.chunk', req.user.id, { fileId, chunkIndex });
    return res.status(201).json({ ok: true });
  } catch (err) {
    console.error('chunk store failed', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

// List file metadata for current user (sender or receiver)
router.get('/', authMiddleware, async (req, res) => {
  try {
    const files = await FileMeta.find({
      $or: [{ sender: req.user.id }, { receiver: req.user.id }],
    })
      .sort({ createdAt: -1 })
      .limit(100);
    await audit('metadata.access', req.user.id, { files: files.length, scope: 'files' });
    return res.json({ files });
  } catch (err) {
    return res.status(500).json({ error: 'server_error' });
  }
});

// Fetch encrypted chunks for authorized user
router.get('/:fileId/chunks', authMiddleware, async (req, res) => {
  try {
    const meta = await FileMeta.findOne({ fileId: req.params.fileId });
    if (!meta) {
      return res.status(404).json({ error: 'file_not_found' });
    }
    if (String(meta.sender) !== req.user.id && String(meta.receiver) !== req.user.id) {
      return res.status(403).json({ error: 'forbidden' });
    }

    const chunks = await FileChunk.find({ fileId: req.params.fileId }).sort({ chunkIndex: 1 });
    await audit('metadata.access', req.user.id, {
      fileId: req.params.fileId,
      chunks: chunks.length,
      scope: 'fileChunks',
    });
    return res.json({ meta, chunks });
  } catch (err) {
    return res.status(500).json({ error: 'server_error' });
  }
});

module.exports = router;
