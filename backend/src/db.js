const mongoose = require('mongoose');
const { MONGO_URI } = require('./config');

mongoose.set('strictQuery', true);

const connectDb = async () => {
  await mongoose.connect(MONGO_URI, {
    serverSelectionTimeoutMS: 5000,
  });
};

module.exports = { connectDb };
