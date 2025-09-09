import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import tokenSetter from '../../utils/tokenSetter.js';
import { deleteAuthCookie, setAuthCookie } from '../../utils/cookiesUtils.js';
import OAuthClient from '../../utils/OAuth.js';
import { findUserByEmail, insertUser, insertOAuthUser, insertEmailOnlyUser, isUserExist } from '../model/userModel.js';
import crypto from 'crypto';
import { sendOTPEmail } from '../../utils/mailer.js';
import { logger } from '../../config/logger.js';
import { redisDel, redisGet, redisSet } from '../../utils/redisUtility.js';
import { promisify } from 'util';


export const registerUserService = async (req, res) => {
  const { firstName, lastName, email, password } = req.body;
  const existingUser = await findUserByEmail(email);
  if (existingUser) return res.status(409).json({ message: 'User already exists' });

  const hashedPassword = await bcrypt.hash(password, 12);
  const user = await insertUser({ firstName, lastName, email, hashedPassword, authType:'PASSWORD' });

  const tokens = tokenSetter(user.id);
  setAuthCookie(res, tokens.refreshToken, tokens.accessToken);
  await redisSet(`refresh:${user.id}`, tokens.refreshToken, { EX: Number(process.env.REDIS_REFRESH_EXPIRY) });
  await redisSet(`session:${user.id}`, tokens.accessToken, { EX: 3600 });



  return res.status(201).json({ message: 'User registered successfully' });
};



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

export const loginUserService = async(req, res)=>{
    const{email, password} = req.body;
    try{
        //check email ID
        const isValidUser = await findUserByEmail(email);
        if(!isValidUser) return res.status(404).json({message:"User doesn't exist, register first"});
        
        //check password
        const isValidPassword = await bcrypt.compare(password, isValidUser.password);
        if(!isValidPassword) return res.status(401).json({message:"Wrong password"});

        const id = isValidUser.id;
        
        //setting tokens
        const tokens=tokenSetter(id);
        setAuthCookie(res, tokens.refreshToken, tokens.accessToken);

        //setting redis
        await redisSet(`refresh:${id}`, tokens.refreshToken,{EX:Number(process.env.REDIS_REFRESH_EXPIRY)});
        await redisSet(`session:${id}`, tokens.accessToken, {EX:3600});

        return res.status(200).json({message:"Logged In", token:tokens.accessToken});

    }catch(err){
        logger.error("Error caught at Login Step:\n", err);
        return res.status(500).json({message:"Somethig went wrong! Please try agin later."});
    }

}

export const logoutUserService = async(req, res)=>{
    try{
        const verifyAsync = promisify(jwt.verify);
        const token = req.cookies.accessToken;
        if(!token) return res.status(400).json({message:"Token required."});

        const decoded = verifyAsync(token, process.env.SECRET);
        deleteAuthCookie(res);

        await Promise.all([
            redisDel(`refresh:${decoded.id}`),
            redisDel(`session:${decoded.id}`)
        ]);

        return res.status(200).json({message:"Successfully logged out"});
    }catch(err){
        logger.error("Error found in the logout section:", err);
        return res.status(500).json({message:"Error in logout section", error:err});
    }
}


export const refreshTokenService = async(req, res)=>{
    const {refreshToken} = req.cookies;
    if (!refreshToken) return res.status(400).json({message:'Missing refresh token'});
    try{
        const verifyAsync = promisify(jwt.verify);
        const decoded = await verifyAsync(refreshToken, process.env.REFRESH_SECRET);        
        const id = decoded.id;
        const storedToken = await redisGet(`refresh:${id}`);

        if(!storedToken || storedToken!==refreshToken){
            return res.status(403).json({message:'Invalid refresh token'});
        }
        const newAccessToken = jwt.sign({id}, process.env.SECRET, {expiresIn:process.env.ACCESS_EXPIRY});

        //setting authCookie:
        setAuthCookie(res, refreshToken, newAccessToken);

        //setting Redis:
        await redisSet(`refresh:${id}`, refreshToken,{EX:Number(process.env.REDIS_REFRESH_EXPIRY)});
        await redisSet(`session:${id}`, newAccessToken, {EX:3600});

        return res.status(200).json({accessToken:newAccessToken});
    }catch(err){
        return res.status(403).json({message:'Token expired or invalid'});
    }
}

export const generateOTPService = async (req, res) => {
  const otp = crypto.randomInt(1000, 9999).toString();
  
  try{
        console.log("Value of req.body", req.body);
        await sendOTPEmail(req.body?.name, req.body?.email, otp);
        // if(!response.ok) return res.status(400).json({message:'Unable to send OTP, check email'});
        console.log(`OTP for ${req.body.email}: ${otp}`);
        await redisSet(`otp:${req.body.email}`, otp, { EX: 300 }); // 5 min expiry
        return res.status(200).json({ message: 'OTP sent to your mail' });
    }catch(err){
        console.error('OTP failure:\n', err);
        return res.status(500).json({message:'Failed to send OTP'});
    }
};

export const verifyOTPService = async (req, res) => {
  const { email, otp } = req.body;
  console.log("value of req.body", req.body);

  try{
    const storedOTP = await redisGet(`otp:${email}`);
    if(!storedOTP || storedOTP !== otp) {
        return res.status(401).json({ message: 'Invalid or expired OTP' });
    }
    await redisDel(`otp:${email}`);
    const user = await isUserExist(email);
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