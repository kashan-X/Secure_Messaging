const { Schema, model } = require('mongoose');

const MessageSchema = new Schema(
  {
    sender: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    receiver: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    ciphertext: { type: String, required: true },
    iv: { type: String, required: true },
    authTag: { type: String, required: true },
    aad: { type: String }, // associated data (e.g., metadata JSON)
    seq: { type: Number, required: true },
    ts: { type: Date, required: true },
    type: { type: String, enum: ['text', 'handshake', 'file'], default: 'text' },
    nonce: { type: String },
    metadata: { type: Schema.Types.Mixed },
  },
  {
    timestamps: { createdAt: true, updatedAt: false },
    versionKey: false,
  }
);

MessageSchema.index({ sender: 1, receiver: 1, seq: 1 }, { unique: true });

module.exports = model('Message', MessageSchema);
