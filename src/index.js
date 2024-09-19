import dotenv from 'dotenv'
dotenv.config({
  path: './.env'
})
import mongoose from 'mongoose';

import app from './app.js';


const start = async (uri,dbname) => {

  if (!uri || undefined === uri) {
    throw new Error('MONGO_URI must be defined');
  }

  try {
    await mongoose.connect(`${uri}/${dbname}`);
    console.log('Connected to MongoDB');
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }

  app.listen(process.env.PORT, () => {
    console.log(`Port is running at ${process.env.PORT}`);
  });
};

start(process.env.MONGO_URI,process.env.MONGO_DB);

// export default start;