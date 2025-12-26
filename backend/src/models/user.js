const { Schema, model } = require('mongoose');

const UserSchema = new Schema(
  {
    username: { type: String, unique: true, required: true, index: true },
    passwordHash: { type: String, required: true },
    identityPublicKey: { type: String, required: true }, // stored for signature verification; private key never stored
    twoFactorEnabled: { type: Boolean, default: false },
    twoFactorSecret: { type: String }, // base32 TOTP secret (optional)
  },
  {
    timestamps: { createdAt: true, updatedAt: false },
    versionKey: false,
  }
);

module.exports = model('User', UserSchema);
