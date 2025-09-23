import { pgConnectTest } from '../config/dbconnection.js';
import { logger } from '../config/logger.js';
import { getRedisClient } from '../config/redisConnection.js';
// import app from '../index.js';

export  function setupHealthCheckUp(app){
    app.get('/healthz', (req, res)=>{
        return res.status(200).json({status:'ok', uptime:process.uptime()});
    });
    app.get('/readyz', async(req, res)=>{
        try{
            //redis check
            const redis = await getRedisClient();
            const pong = await redis.ping();
            if(pong!=='PONG') throw new Error('Unxepected Redis response');

            // postgres check
            await pgConnectTest();

            return res.status(200).json({ready:true, redis:'Connected', postgres:'Connected'});
        }catch(err){
            logger.error('🔴 Readiness check failed:', err);
            return res.status(503).json({ready:false, error:err.message||'unknown failure'});
        }
    });
}