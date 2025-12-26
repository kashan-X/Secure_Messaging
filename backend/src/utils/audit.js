const Log = require('../models/log');
const { appendLogLine } = require('./logFile');

// Persist security-relevant events to Mongo and stdout.
const audit = async (event, userId, details = {}) => {
  try {
    const entry = await Log.create({
      event,
      userId,
      details,
    });
    // Mirror to stdout for quick debugging
    // Avoid logging sensitive plaintext; only metadata is included.
    console.info(`[audit] ${event}`, {
      userId: userId ? userId.toString() : undefined,
      details,
      at: entry.createdAt.toISOString(),
    });
    appendLogLine(
      JSON.stringify({
        event,
        userId: userId ? userId.toString() : undefined,
        details,
        at: entry.createdAt.toISOString(),
      })
    );
  } catch (err) {
    console.error('[audit] failed to write log', err);
  }
};

module.exports = { audit };
