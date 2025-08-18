import express from 'express';
import {logger} from '../../config/logger.js'
// import { registerValidator } from '../middleware/validator.js';
import { addColumn, generateOTP, loginUser, logoutUser, refreshToken, registerUser, registerUserWithOAuth, verifyOTP } from '../controllers/authController.js';
import { rateLimiter } from '../middleware/rateLimiter.js';
import { verifySession } from '../middleware/verifySession.js';

const authRouter = express.Router();

authRouter.get('/', (req, res)=>{
    res.status(200).send("Welcome to the authRouter");
    logger.info("auth route / Get request hit!");
});


//   API route starter: /api/v1/auth/
// authRouter.post('/login/google-auth',registerUser);
authRouter.post('/register', registerUser)
authRouter.post('/login/OAuth', rateLimiter, registerUserWithOAuth);
authRouter.post('/logout', verifySession, logoutUser);
authRouter.post('/login', rateLimiter, loginUser);
authRouter.post('/otp/generate', generateOTP);
authRouter.post('/otp/verify', verifyOTP);
authRouter.post('/refresh', refreshToken );
authRouter.get('/addColumn', addColumn)

export default authRouter;