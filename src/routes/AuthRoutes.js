import express from 'express';
import {logger} from '../../config/logger.js'
// import { registerValidator } from '../middleware/validator.js';
import {
    //  addColumn, 
     generateOTP, 
     loginUser, 
     logoutUser, 
     refreshToken, 
     registerUser, 
     registerUserWithOAuth, 
     verifyOTP 
    } from '../controllers/authController.js';
import { rateLimiter } from '../../middleware/rateLimiter.js';
import { verifySession } from '../../middleware/verifySession.js';
import { registerValidator } from '../../middleware/validator.js';

const authRouter = express.Router();
//change made in the other tab
authRouter.get('/', (req, res)=>{
    res.status(200).json({message:"Welcome to the authRouter"});
    logger.info("auth route / Get request hit!");
});


//   API route starter: /api/v1/auth/

authRouter.post('/register',registerValidator, registerUser)
authRouter.post('/login/OAuth', registerUserWithOAuth);
authRouter.post('/logout', verifySession, logoutUser);
authRouter.post('/login', loginUser);
authRouter.post('/otp/generate', generateOTP);
authRouter.post('/otp/verify', verifyOTP);
authRouter.post('/refresh',verifySession, refreshToken );

// authRouter.get('/addColumn', addColumn)

export default authRouter;