const { app } = require('./app');
const { connectDb } = require('./db');
const { PORT } = require('./config');

const start = async () => {
  try {
    await connectDb();
    app.listen(PORT, () => console.log(`API listening on :${PORT}`));
  } catch (err) {
    console.error('failed to start server', err);
    process.exit(1);
  }
};

start();

process.on('unhandledRejection', (err) => {
  console.error('unhandled rejection', err);
});
