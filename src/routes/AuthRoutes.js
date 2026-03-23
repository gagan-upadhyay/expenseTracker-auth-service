import express from 'express';
import {logger} from '../../config/logger.js'
// import { registerValidator } from '../middleware/validator.js';
import {
    forgotPassword,
     generateOTP, 
     loginUser, 
     logoutUser, 
     refreshToken, 
     registerUser, 
     registerUserWithOAuth, 
    resetPassword, 
     verifyOTP 
    } from '../controllers/authController.js';

import { rateLimiter } from '../../middleware/rateLimiter.js';
import { verifySession } from '../../middleware/verifySession.js';
import { registerValidator, validateMagicLinkMiddleware } from '../../middleware/validator.js';
import { setupHealthCheckUp } from '../../utils/setupHealthcheckUp.js';

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
authRouter.post('/otp/generate',verifySession, generateOTP);
authRouter.post('/otp/verify', verifyOTP);
authRouter.post('/refresh',verifySession, refreshToken);
authRouter.post('/forgot-password', forgotPassword)
authRouter.get('/password-reset', validateMagicLinkMiddleware, resetPassword);


// authRouter.post('/logs', clientLogs)
// authRouter.get('/health', setupHealthCheckUp);
// authRouter.get('/addColumn', addColumn)

export default authRouter;


// flow:
// first user will go to /forgot-password
// 
// 
// 
// 
// 
// 
// 
// 