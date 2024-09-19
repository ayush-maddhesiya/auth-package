import express from 'express'
import {
  login,
  registerUser,
  logOut,
  resetPassword,
  forgetPassword,
  verifyEmailToken
 } from "../controllers/user.controller.js"
const router = express.Router();


router.get('/auth/login',login );
router.post('/auth/register',registerUser );
router.get('/auth/logout',logOut );
router.post('/auth/reset-password',resetPassword );
router.post('/auth/forget-password',forgetPassword );
router.post("/auth/verityEmail",verifyEmailToken);

router.post('/auth/loginuser', async (req, res) => {
  const { username, password } = req.body;
  try {
    const response = await loginUser(username, password);
    res.json(response);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

router.get("/hello", async (req, res) => {
  res.send("hello");
});

export default router