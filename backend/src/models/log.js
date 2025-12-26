const { Schema, model } = require('mongoose');

const LogSchema = new Schema(
  {
    event: { type: String, required: true },
    userId: { type: Schema.Types.ObjectId, ref: 'User' },
    details: { type: Schema.Types.Mixed },
  },
  {
    timestamps: { createdAt: true, updatedAt: false },
    versionKey: false,
  }
);

module.exports = model('Log', LogSchema);
