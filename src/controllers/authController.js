import jwt from 'jsonwebtoken';
import { logger } from '../../config/logger.js';
import OAuthClient from '../utils/OAuth.js';
import {Pool} from 'pg';
import {redisClient } from '../utils/redisConnection.js';
import { sendOTPEmail } from '../utils/mailer.js';
import crypto from 'crypto';
import bcrypt from 'bcrypt';

const pool = new Pool({
    connectionString:process.env.POSTGRES_URL
});

export const registerUser = async(req, res)=>{
    const {firstName, lastName, email, password} = req.body;
    // console.log(req.body);
    
   try{
        const userExists = await pool.query(`SELECT * FROM users WHERE EMAIL=$1`, [email]);

        if(userExists.rows.length>0){
            return res.status(409).json({message:'User already exists in db'});
        }
        const hashedPassword =await bcrypt.hash(password, 12);
        console.log("value of hashed password:", hashedPassword);
        
        const userSaved = await pool.query(`
        INSERT INTO users(firstname, lastname, email, password, auth_type, created_at)
        VALUES($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)`, 
        [firstName, lastName, email, hashedPassword, 'PASSWORD']);
        
        if(!userSaved){
            return res.status(404).json({message:'Something went worng'});
        }
        //***************below logic will right away give the access to app no need to go to login page now */
        const accessToken = jwt.sign({email}, process.env.SECRET, {expiresIn:process.env.ACCESS_EXPIRY});
        console.log("AccessToken:", accessToken);

        const refreshToken = jwt.sign({email}, process.env.REFRESH_SECRET, {expiresIn:process.env.REFRESH_EXPIRY});

        console.log("RefreshToken:", refreshToken);

        await redisClient.set(`refresh:${email}`, refreshToken, {EX:Number(process.env.REDIS_REFRESH_EXPIRY)});
        await redisClient.set(`session:${email}`, accessToken, {EX:3600});
        //******************************************************************************* */
        return res.status(201).json({message:'User registered successfully', 
            user:userSaved.rows[0]
        });
    }catch(err){
        logger.error('Error at registerUser:', err);
        // throw new Error('Error in registering user:', err);
        res.status(500).json({message:'Something went worng with register'});

    }
}

export const loginUser = async(req, res)=>{
    const {email, password} = req.body;
    try{
        const result = await pool.query(`SELECT * from users where EMAIL=$1`, [email]);
        if(!result.rows.length>0){
            res.status(404).json({message:"User not registered!"});
        }
        
        

    }catch(err){
        logger.error("Error caught at Login step:\n",err);
    }

}

export const registerUserWithOAuth = async (req, res)=>{
    // console.log("value of req from comntroller", req);
    
    console.log("Value of req.headers.authorization",req.headers.authorization);
    const tokenId = req.headers.authorization;
    if(!tokenId || !tokenId.startsWith("Bearer ")) return res.status(401).send("Missing or malformed token");
    try{
        const ticket = await OAuthClient.verifyIdToken({
            idToken:tokenId.slice(7),
            audience:process.env.GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();

        console.log("value of payload from authController: ",payload);

        if(payload.aud!==process.env.GOOGLE_CLIENT_ID) return res.status(401).send("Unauthorized");
        
        const existingUser = await pool.query(`SELECT * FROM users WHERE EMAIL=$1`, [payload.email]);

        if(existingUser.rows.length!==0){
            const authToken = jwt.sign({email:payload.email, name:payload.name}, process.env.SECRET, {expiresIn:'1h'});
            await redisClient.set(`session:${payload.email}`, authToken, {'EX':3600});
            return res.json(authToken);
        }else{
            await pool.query(`INSERT INTO users (email, firstName, auth_type, created_at) VALUES ($1,$2,$3,CURRENT_TIMESTAMP) `, [payload.email, payload.name, 'OAUTH']);
            const authToken = jwt.sign({email:payload.email, name:payload.name},process.env.SECRET, {expiresIn:'1h'} );
            await redisClient.set(`session:${payload.email}`, authToken, {'EX':3600});
            return res.json({authToken});
        }
       
    }catch(err){
        logger.error('Error at registerUser with OAuth:\n', err);
    }
}


//****************************Token login logic******************** */
export const loginWithTokens = async(req, res)=>{
    const {email} = req.body;
    const accessToken = jwt.sign({email}, process.env.SECRET, {expiresIn:process.env.ACCESS_EXPIRY});

    const refreshToken = jwt.sign({email}, process.env.REFRESH_SECRET, {expiresIn:process.env.REFRESH_EXPIRY});

    await redisClient.set(`refresh:${email}`, refreshToken, 'EX', process.env.REFRESH_EXPIRY);
    res.status(200).json({accessToken, refreshToken});
}
export const refreshToken = async(req, res)=>{
    const {refreshToken} = req.body;
    try{
        const decoded = jwt.verify(refreshToken, process.env.REFRESH_SECRET);
        const email = decoded.email;

        const storedToken  = await redisClient.get(`refresh:${email}`);
        if(!storedToken || storedToken!==refreshToken){
            return res.status(403).json({message: 'Invalild refresh token'});
        }
        const newAccessToken = jwt.sign({email}, process.env.SECRET, {expiresIn:process.env.ACCESS_EXPIRY});
        res.status(200).json({accessToken:newAccessToken});
    }catch(err){
        res.status(403).json({message:'Token expired or invalid'});
    }
    
}

//********************log out logic*************** */

export const logoutUser = async(req, res)=>{
    const token = req.headers.authorization?.split(' ')[1];
    if(!token) return res.status(400).json({message:'Token required'});

    const decoded = jwt.decode(token);
    await redisClient.del(`refresh:${decoded.email}`);
    await redisClient.del(`session:${decoded.email}`);

    res.status(200).json({message:'Successfully logged out'});
};

//**********generate OTP***************** */

export const generateOTP = async (req, res)=>{
    const {email, name} = req.body;
    const otp = crypto.randomInt(100000, 999999).toString();

    //storing otp in redis with 5 ins expiry:
    await redisClient.set(`otp:${email}`, otp, {'EX': 300}) //300 seconds

    //send otp via email/sms
    const response = await sendOTPEmail(name, email, otp);
    logger.info(response);
    console.log(`OTP from ${email}: ${otp}`);
    res.status(200).json({message:'OTP sent to your mail'});
}

export const verifyOTP = async (req, res)=>{
    const {email, otp} = req.body;
    console.log('value of email and otp:', email, otp);

    const storedOTP = await redisClient.get(`otp:${email}`);
    console.log("value of storeOTP:", storedOTP);
    if(!storedOTP || storedOTP!== otp){
        return res.status(401).json({message:'Invalid or expired OTP'});
    }
    //clearing OTP after use
    await redisClient.del(`otp:${email}`);
    const existingUser = await pool.query(`SELECT * FROM users WHERE email=$1`, [email]);
    console.log("Value of existingUser from verfiyOTP:",existingUser);
    if(existingUser.rows.length===0){
        await pool.query('INSERT INTO users (email) VALUES ($1)', [email]);
    }
    const authToken = jwt.sign({email}, process.env.SECRET, {expiresIn:'1h'});
    await redisClient.set(`session:${email}`, authToken, {'EX': 3600});
    res.status(200).json({authToken});
}

