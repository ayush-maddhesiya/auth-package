import express from 'express'

const app = express();

app.use(cors({
  origin: process.env.CORS_ORIGIN,
  credentials: true
}))
app.use(Express.json({ limit: "16kb"}))
app.use(Express.urlencoded({extended: true, limit : "16kb"}))
app.use(cookieParser())

app.get('/', (req, res) => {
  res.send('Hello World!');
});

export default app;