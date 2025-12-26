const express = require('express');
const User = require('../models/user');
const { authMiddleware } = require('../middleware/auth');

const router = express.Router();

router.get('/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('username identityPublicKey createdAt');
    return res.json({ user });
  } catch (err) {
    return res.status(500).json({ error: 'server_error' });
  }
});

// Public endpoint to fetch identity public key for verifying signatures.
router.get('/:username/public-key', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username }).select('identityPublicKey username');
    if (!user) {
      return res.status(404).json({ error: 'not_found' });
    }
    return res.json({ id: user._id, username: user.username, identityPublicKey: user.identityPublicKey });
  } catch (err) {
    return res.status(500).json({ error: 'server_error' });
  }
});

module.exports = router;
