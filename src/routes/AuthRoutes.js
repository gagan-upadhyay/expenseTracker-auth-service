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
import { subscribe, unsubscribe, sendTest, listAllSubscriptions, cleanupSubscriptions } from '../controllers/notificationController.js';
import adminAuth from '../adminAuth.js';

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
authRouter.post('/otp/verify', verifySession, verifyOTP);
authRouter.post('/refresh', refreshToken);
authRouter.post('/forgot-password', forgotPassword)
authRouter.get('/password-reset', validateMagicLinkMiddleware, resetPassword);


// authRouter.post('/logs', clientLogs)
// authRouter.get('/health', setupHealthCheckUp);
// authRouter.get('/addColumn', addColumn)

authRouter.post('/notifications/subscribe', verifySession, subscribe);
authRouter.post('/notifications/unsubscribe', verifySession, unsubscribe);
// test endpoint to send a notification (can be restricted to admins)
authRouter.post('/notifications/send-test', verifySession, sendTest);

// Admin-only endpoints
authRouter.get('/notifications/list', adminAuth, listAllSubscriptions);
authRouter.post('/notifications/cleanup', adminAuth, cleanupSubscriptions);

export default authRouter;
