import express from 'express'

import {login,} from "../controllers/user.controller.js"
const router = express.Router();


router.get('/auth/login',login );

export default router