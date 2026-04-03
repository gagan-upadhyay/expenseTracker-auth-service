import * as bcrypt from "bcrypt";
import jwt from 'jsonwebtoken';
import tokenSetter from '../../utils/tokenSetter.js';
import { deleteAuthCookie, setAuthCookie } from '../../utils/cookiesUtils.js';
import OAuthClient from '../../utils/OAuth.js';
import { 
    findUserByEmail, 
    insertUser, 
    insertOAuthUser, 
    insertEmailOnlyUser,
    updateField, 
} from '../model/userModel.js';
import crypto from 'crypto';
import { sendOTPEmail, sendPasswordMagicLink } from '../../utils/mailer.js';
import { logger } from '../../config/logger.js';
import { redisDel, redisGet, redisSet } from '../../utils/redisUtility.js';
import { promisify } from 'util';



// ================= REGISTER =================
export const registerUserService = async (req, res) => {
    const { firstName, lastName, email, password } = req.body;

    try {
        const existingUser = await findUserByEmail(email);
        if (existingUser) return res.status(409).json({ message: 'User already exists' });

        const hashedPassword = await bcrypt.hash(password, 12);
        const user = await insertUser({ firstName, lastName, email, hashedPassword, authType:'PASSWORD' });

        const sessionId = crypto.randomUUID();

        const accessToken = jwt.sign(
            { id: user.id },
            process.env.SECRET,
            { expiresIn: process.env.ACCESS_EXPIRY }
        );

        const refreshToken = jwt.sign(
            { id: user.id, sessionId },
            process.env.REFRESH_SECRET,
            { expiresIn: process.env.REFRESH_EXPIRY }
        );

        setAuthCookie(res, refreshToken, accessToken);

        await redisSet(
            `refresh:${user.id}:${sessionId}`,
            refreshToken,
            { EX: Number(process.env.REDIS_REFRESH_EXPIRY) }
        );

        return res.status(201).json({
            accessToken,
            message: 'User registered successfully'
        });

    } catch (err) {
        logger.error('Register error:', err);
        return res.status(500).json({ success:false });
    }
};


const isEmailExist = async(email)=>{
    try{
        const result = await findUserByEmail(email);
        console.log('Value of result from authService:\n', result);
        if(result.auth_type ==='GOOGLE'){
            return 'OAUTH AC'
        }
        return result;
    }catch(err){
        console.error('Error while validating email', err);
    }
}

export const registerUserWithOAuthService = async(req, res)=>{
    const tokenID = req.headers.authorization;
    console.log("Value of tokenID", tokenID);

    if(!tokenID || !tokenID.startsWith("Bearer ")) return res.status(401).json({message:'Missing or malformed token'});

    console.log("value of tokenID.slice(7)", tokenID.slice(7));
    try{
        const ticket = await OAuthClient.verifyIdToken({
            idToken:tokenID.slice(7),
            audience:process.env.GOOGLE_CLIENT_ID,
        });

        const payload = ticket.getPayload();
        if(payload.aud !== process.env.GOOGLE_CLIENT_ID) return res.status(401).json({message:'Unauthorized'});
        
        const existingUser = await findUserByEmail(payload.email);
        console.log("Value of existingUser", existingUser);

        if(existingUser){
            
            //setting access and refresh token
            const tokens = tokenSetter(existingUser.id);

           // setting http only cookie
            setAuthCookie(res, tokens.refreshToken, tokens.accessToken, true);
                        
            //setting redis session and refresh
            await redisSet(`session:${existingUser.id}`, tokens.accessToken, {'EX':3600});
            await redisSet(`refresh:${existingUser.id}`, tokens.refreshToken,{EX:Number(process.env.REDIS_REFRESH_EXPIRY)});


            return res.status(200).json({message:'Logged in successfully',tokens});

        }else{
            const result = insertUser(payload.given_name, payload.family_name, payload.email, null, 'Google', payload.picture);

            const tokens = tokenSetter(result.id);

            redisSet(`session:${result.id}`, tokens.accessToken, {'EX':3600});
            redisSet(`refresh:${result.id}`, tokens.refreshToken, {EX:Number(process.env.REDIS_REFRESH_EXPIRY)});

            return res.status(200).json({message:'Logged In successfully'});
        }

    }catch(err){
        logger.error("Error while logging with Google Oauth2", err);
        return res.status(500).json({message:'Something went wrong! Please try again later'});
    }
}

// ================= LOGIN =================
export const loginUserService = async (req, res) => {
    const { email, password } = req.body;

    try {
        if (!email || !password)
            return res.status(400).json({ success:false ,error:"Email and password are required"});

        const user = await findUserByEmail(email);
        if (!user) return res.status(404).json({ success:false, error:"User doesn't exist, register first"});
        

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword)
            return res.status(401).json({ success:false, error:'Wrong Password' });

        const sessionId = crypto.randomUUID();

        const accessToken = jwt.sign(
            { id: user.id },
            process.env.SECRET,
            { expiresIn: process.env.ACCESS_EXPIRY }
        );

        const refreshToken = jwt.sign(
            { id: user.id, sessionId },
            process.env.REFRESH_SECRET,
            { expiresIn: process.env.REFRESH_EXPIRY }
        );
        console.log(`Value of refreshToken:${refreshToken} and accessToken:${accessToken}`);

        setAuthCookie(res, refreshToken, accessToken);

        await redisSet(
            `refresh:${user.id}:${sessionId}`,
            refreshToken,
            { EX: Number(process.env.REDIS_REFRESH_EXPIRY) }
        );

        return res.status(200).json({
            success: true,
            accessToken
        });

    } catch (err) {
        logger.error("Login error:", err);
        return res.status(500).json({ success:false });
    }
};
// ================= LOGOUT (PER DEVICE) =================
export const logoutUserService = async (req, res) => {
    console.log("Inside logoutUser Service");
    try {
        const { refreshToken } = req.cookies;
        if (!refreshToken)
            return res.status(401).json({ success:false });

        const decoded = jwt.verify(refreshToken, process.env.REFRESH_SECRET);
        const { id, sessionId } = decoded;

        await redisDel(`refresh:${id}:${sessionId}`);

        deleteAuthCookie(res);

        return res.status(200).json({
            success: true,
            message: "Logged out"
        });

    } catch (err) {
        logger.error("Logout error:", err);
        return res.status(403).json({ success:false });
    }
};
// ================= REFRESH =================
export const refreshTokenService = async (req, res) => {
    const { refreshToken: oldToken } = req.cookies;
    console.log(`Value of oldToken:${oldToken}`);

    if (!oldToken)
        return res.status(401).json({ success:false });

    try {
        const verifyAsync = promisify(jwt.verify);
        const decoded = await verifyAsync(oldToken, process.env.REFRESH_SECRET);

        const { id, sessionId: oldSessionId } = decoded;
        console.log(`Value of oldSessionId:${oldSessionId}`);
        const storedToken = await redisGet(`refresh:${id}:${oldSessionId}`);

        if (!storedToken || storedToken !== oldToken) {
            await redisDel(`refresh:${id}:${oldSessionId}`);
            return res.status(403).json({ success:false });
        }

        const newSessionId = crypto.randomUUID();

        const newAccessToken = jwt.sign(
            { id },
            process.env.SECRET,
            { expiresIn: process.env.ACCESS_EXPIRY }
        );

        const newRefreshToken = jwt.sign(
            { id, sessionId: newSessionId },
            process.env.REFRESH_SECRET,
            { expiresIn: process.env.REFRESH_EXPIRY }
        );

        // rotate
        await redisDel(`refresh:${id}:${oldSessionId}`);

        await redisSet(
            `refresh:${id}:${newSessionId}`,
            newRefreshToken,
            { EX: Number(process.env.REDIS_REFRESH_EXPIRY) }
        );

        setAuthCookie(res, newRefreshToken, newAccessToken);

        return res.status(200).json({
            success: true,
            accessToken: newAccessToken
        });

    } catch (err) {
        return res.status(403).json({ success:false });
    }
};


// ================= LOGOUT ALL DEVICES =================
export const logoutAllDevicesService = async (req, res) => {
    try {
        const { refreshToken } = req.cookies;
        const decoded = jwt.verify(refreshToken, process.env.REFRESH_SECRET);

        const { id } = decoded;

        const keys = await redisClient.keys(`refresh:${id}:*`);

        for (const key of keys) {
            await redisDel(key);
        }

        deleteAuthCookie(res);

        return res.status(200).json({
            success: true,
            message: "Logged out from all devices"
        });

    } catch (err) {
        return res.status(500).json({ success:false });
    }
};

export const generateOTPService = async (req, res) => {
  const otp = crypto.randomInt(1000, 9999).toString();
  
  try{
        console.log("Value of req.body", req.body);
        const emailAlreadyInUse = await findUserByEmail(req.body.email);
        console.log("Value of emailAlreadyInUse:\n", emailAlreadyInUse);
        if(emailAlreadyInUse && req.body.type==='emailChange'){
            return res.status(400).json({success:false, error:'Email already in use'});
        }
        const result = await sendOTPEmail(req.body?.name, req.body?.email, otp);
        // if(!response.ok) return res.status(400).json({message:'Unable to send OTP, check email'});
        console.log("Value of res from generateOTservice", result);
        if(result.success){
            console.log(`OTP for ${req.body.email}: ${otp}`);
            await redisSet(`otp:${req.body.email}`, otp, { EX: 300 });
            console.log("Inside if statemenmt");
            return res.status(200).json({success:true, message:result.message});
        }else if(!result.success){
            return res.status(404).json({success:false, error:result.error});
        
        }else{
            console.log("Outside the if statement");
            return res.status(404).json({success:false, error:'Failed to send OTP'});
        }

    }catch(err){
        let errorMessage;
        if (err instanceof Error){
            errorMessage=err.message;
        }
        console.error('OTP failure:\n', errorMessage);
        return res.status(500).json({success:false, error:errorMessage});
    }
};
export const verifyOTPService = async (req, res) => {
  const { email, otp, useForLogin } = req.body;
  console.log("value of req.body from verfiyOTP:\n", req.body);

  try{
    const storedOTP = await redisGet(`otp:${email}`);
    console.log("Value of storedOTP:\n", storedOTP, typeof(storedOTP));

    if(storedOTP!== otp) {
        console.log(`checking if storedOTP===otp: ${storedOTP===otp}`);
        return res.status(401).json({ success:false, error: 'Invalid or expired OTP' });
    }
    await redisDel(`otp:${email}`);
    if(!useForLogin){
        return res.status(200).json({success:true, message:'OTP verified successfully'});
    }
    const user = await findUserByEmail(email);
    // console.log("value of user froem authService verifyOTP:\n", user);
    if (!user) await insertEmailOnlyUser(email);
    const authToken = jwt.sign({ email }, process.env.SECRET, { expiresIn: '1h' });
    await redisSet(`session:${email}`, authToken, { EX: 3600 });
    return res.status(200).json({ authToken });

  }catch(err){
    console.error("Error at verifying the OTP", err);
    return res.status(500).json({message:'Something went wrong, please try again later.'});
  }
};

export const forgotPasswordService=async(req, res)=>{
    try{
        const {email} = req.body;
        const result = await isEmailExist(email);
        // console.log('Value fo result form forgetPasword fn:', result);
        
        if(result ==='OAUTH AC'){
            return res.status(400).json({success:false, error:"Can't change password for OAUTH type accounts"});
        }
        if(!result){
        return res.status(404).json({success:false, error:"User doesn't exists"})
        }
        else if(result==='Email is not valid'){
            return res.status(400).json({success:false, error:'Email is not valid'})
        }
        const token = jwt.sign({email}, process.env.SECRET, {expiresIn:'15m'});
        const isMailSent = await sendPasswordMagicLink(email, token);
        if(!isMailSent){
            return res.status(404).json({success:false, error:'Failed to send magic link'});
        }
        await redisSet(`resetPassword:${email}`, token, {EX:900});
        return res.status(200).json({success:true, message:'Magic link sent', token:token});
    }catch(err){
        console.error('Error while changing password', err);
        return res.status(500).json({message:'Something went wrong, please try again later.'})
    }
}

export const resetPasswordService = async(req, res)=>{
    const email = req.email;
    //---------------can be commented out---------
    const isUserExists = await findUserByEmail(req.email);
    if(!isEmailExist){
        return req.status(400).json({message:'Back-off you sucker!!'});
    }
//---------------------------------------
    const {password} = req.body.password;
    const hashedPassword = await bcrypt.hash(password, 12);
    const result = await updateField('password', hashedPassword, email);
    if(!result){
        return res.status(400).json({message:'Failure when saving password'});
    }
    return res.status(201).json({message:'Password changed successfully'});
}