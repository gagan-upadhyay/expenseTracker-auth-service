import jwt from 'jsonwebtoken';
import { redisClient } from '../utils/redisConnection.js';

export const verifySession = async(req, res, next)=>{
    try{
        console.log("From verify session");
        const token = req.cookies.accessToken;
        console.log("Value of token from verifySession of user service:", token);
        if(!token) return res.status(401).json({message:'Token missing'});
        const decoded = jwt.verify(token, process.env.SECRET);
        console.log("Value of decoded from auth verifySession:\n", decoded);

        const cachedToken = await redisClient.get(`session:${decoded.id}`);
        if(cachedToken!== token){
            return res.status(401).json({message:'Invalid or expired token'})
        }
        req.user=decoded;
        next();
    }catch(err){
        res.status(401).json({message:'Unauthorized!'});
    }
};