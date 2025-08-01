import jwt from 'jsonwebtoken';
import { redisClient } from '../utils/redisConnection.js';

export const verifySession = async(req, res, next)=>{
    try{
        const token = req.headers.authorization?.split(' ')[1];
        if(!token) return res.status(401).json({message:'Token missing'});
        const decoded = jwt.verify(token, process.env.SECRET);
        const email = decoded.email;

        const cachedToken = await redisClient.get(`session:${email}`);
        if(cachedToken!== token){
            return res.status(401).json({message:'Invalid or expired token'})
        }
        req.user=decoded;
        next();
    }catch(err){
        res.status(401).json({message:'Unauthorized!'});
    }
};