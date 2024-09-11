import mongoose from 'mongoose';
import dotenv from 'dotenv'
import app from './app.js';

dotenv.config("./.env");

const start = async () => {

  if (!process.env.MONGO_URI || undefined === process.env.MONGO_URI) {
    throw new Error('MONGO_URI must be defined');
  }

  try {
    await mongoose.connect(`${process.env.MONGO_URI}/${process.env.MONGO_DB}`);
    console.log('Connected to MongoDB');
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }

  app.listen(process.env.PORT, () => {
    console.log(`Port is running at ${process.env.PORT}`);
  });
};

start();

// export default start;