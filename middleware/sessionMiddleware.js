import { RedisStore } from 'connect-redis';
import session from 'express-session';
import {getRedisClient} from '../config/redisConnection.js';

const sessionMiddleware = session({
    store: new RedisStore({client:getRedisClient}),
    secret:process.env.SESSION_SECRET,
    resave:false,
    saveUninitialized:false,
    cookie:{
        httpOnly:true,
        secure:process.env.NODE_ENV==='production',
        sameSite:'lax',
        maxAge:1000*60*60*2 // 2 hours
    }
});
export default sessionMiddleware;