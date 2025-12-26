const fs = require('fs');
const path = require('path');

const logPath = path.join(__dirname, '..', '..', 'logs.txt');

const appendLogLine = (line) => {
  try {
    fs.appendFileSync(logPath, `${line}\n`, { encoding: 'utf8' });
  } catch (err) {
    console.error('[file-log] failed to append', err);
  }
};

module.exports = { appendLogLine, logPath };
