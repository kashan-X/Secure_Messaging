const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const User = require('../models/user');
const { audit } = require('../utils/audit');
const { JWT_SECRET, TOKEN_TTL } = require('../config');
const { authMiddleware } = require('../middleware/auth');

const router = express.Router();

router.post('/register', async (req, res) => {
  const { username, password, identityPublicKey } = req.body || {};

  if (!username || !password || !identityPublicKey) {
    return res.status(400).json({ error: 'missing_fields' });
  }

  try {
    const existing = await User.findOne({ username });
    if (existing) {
      return res.status(409).json({ error: 'username_taken' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({ username, passwordHash, identityPublicKey });
    await audit('auth.register', user._id, { username });

    return res.status(201).json({ id: user._id, username: user.username });
  } catch (err) {
    console.error('register failed', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

router.post('/login', async (req, res) => {
  const { username, password, totpCode } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'missing_fields' });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      await audit('auth.fail', null, { username, reason: 'user_not_found' });
      return res.status(401).json({ error: 'invalid_credentials' });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      await audit('auth.fail', user._id, { username, reason: 'bad_password' });
      return res.status(401).json({ error: 'invalid_credentials' });
    }

    if (user.twoFactorEnabled) {
      if (!totpCode) {
        await audit('auth.fail', user._id, { username, reason: 'missing_totp' });
        return res.status(401).json({ error: 'totp_required' });
      }
      const okTotp = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: totpCode,
        window: 1,
      });
      if (!okTotp) {
        await audit('auth.fail', user._id, { username, reason: 'bad_totp' });
        return res.status(401).json({ error: 'invalid_totp' });
      }
    }

    const token = jwt.sign({ sub: user._id.toString(), username: user.username }, JWT_SECRET, {
      expiresIn: TOKEN_TTL,
    });
    await audit('auth.success', user._id, { username });

    return res.json({ token, user: { id: user._id, username: user.username } });
  } catch (err) {
    console.error('login failed', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

// Start TOTP setup (returns secret + otpauth URL; requires confirmation)
router.post('/2fa/setup', authMiddleware, async (req, res) => {
  const secret = speakeasy.generateSecret({
    name: `E2EE (${req.user.username})`,
    length: 20,
  });
  try {
    await User.findByIdAndUpdate(req.user.id, {
      twoFactorSecret: secret.base32,
      twoFactorEnabled: false,
    });
    await audit('auth.2fa.setup', req.user.id, { username: req.user.username });
    return res.json({ base32: secret.base32, otpauth_url: secret.otpauth_url });
  } catch (err) {
    console.error('2fa setup failed', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

// Confirm and enable TOTP with a code
router.post('/2fa/verify', authMiddleware, async (req, res) => {
  const { totpCode } = req.body || {};
  if (!totpCode) {
    return res.status(400).json({ error: 'missing_totp' });
  }
  try {
    const user = await User.findById(req.user.id);
    if (!user || !user.twoFactorSecret) {
      return res.status(400).json({ error: 'no_secret' });
    }
    const okTotp = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: totpCode,
      window: 1,
    });
    if (!okTotp) {
      await audit('auth.2fa.verify.fail', req.user.id, { username: req.user.username });
      return res.status(401).json({ error: 'invalid_totp' });
    }
    user.twoFactorEnabled = true;
    await user.save();
    await audit('auth.2fa.enabled', req.user.id, { username: req.user.username });
    return res.json({ ok: true });
  } catch (err) {
    console.error('2fa verify failed', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

// Disable TOTP
router.post('/2fa/disable', authMiddleware, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user.id, { twoFactorEnabled: false, twoFactorSecret: null });
    await audit('auth.2fa.disabled', req.user.id, { username: req.user.username });
    return res.json({ ok: true });
  } catch (err) {
    console.error('2fa disable failed', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

module.exports = router;
