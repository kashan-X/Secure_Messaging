const { Schema, model } = require('mongoose');

const FileMetaSchema = new Schema(
  {
    fileId: { type: String, unique: true, required: true },
    sender: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    receiver: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    totalChunks: { type: Number, required: true },
    fileName: { type: String },
    fileSize: { type: Number },
    mimeType: { type: String },
  },
  {
    timestamps: { createdAt: true, updatedAt: false },
    versionKey: false,
  }
);

const FileChunkSchema = new Schema(
  {
    fileId: { type: String, required: true, index: true },
    chunkIndex: { type: Number, required: true },
    ciphertext: { type: String, required: true },
    iv: { type: String, required: true },
    authTag: { type: String, required: true },
    aad: { type: String },
    sender: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    receiver: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  },
  {
    timestamps: { createdAt: true, updatedAt: false },
    versionKey: false,
  }
);

FileChunkSchema.index({ fileId: 1, chunkIndex: 1 }, { unique: true });

module.exports = {
  FileMeta: model('FileMeta', FileMetaSchema),
  FileChunk: model('FileChunk', FileChunkSchema),
};
