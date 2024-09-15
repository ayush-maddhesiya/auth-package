import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser';
const app = express();
import {
  
} from './routes/user.route.js'
app.use(cors({
  origin: process.env.CORS_ORIGIN,
  credentials: true
}))
app.use(express.json({ limit: "16kb"}))
app.use(express.urlencoded({extended: true, limit : "16kb"}))
app.use(cookieParser())

import auth from './routes/user.route.js'
app.use('/auth',auth);
// console.log(auth);


app.get("/hello", async (req, res) => {
  res.send("hello");
});


export default app;