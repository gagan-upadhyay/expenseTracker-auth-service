import express from 'express';
import '@dotenvx/dotenvx/config'
import cors from 'cors';
import compression from 'compression';
import morgan from 'morgan';
import authRouter from './src/routes/AuthRoutes.js';
import {logger} from './config/logger.js';
import cookieParser from 'cookie-parser';
import { helmetConfig } from './config/helmet.config.js';
import { setupHealthCheckUp } from './utils/setupHealthcheckUp.js';
import setupGracefulShutDown from './utils/setupGracefulShutdown.js';
import { getRedisClient } from './config/redisConnection.js';
import {  pool } from './config/dbconnection.js';

// import timeout from 'connect-timeout';

const app = express();

const corsOptions = {
    origin:[
        'http://192.168.0.126:3000',
        'http://localhost:3000',
        'https://expense-tracker-git-newbranch-gagans-projects-00cb1a77.vercel.app',
        'https://expense-tracker-self-rho-12.vercel.app',
        'https://expense-tracker-gagans-projects-00cb1a77.vercel.app'
    ],
    credentials:true
}

app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());
app.use(helmetConfig)

if(process.env.NODE_ENV === 'development'){
    app.use(morgan('dev'));
}
app.use(compression());
app.use((err, req, res, next)=>{
    console.error(err.stack);
    logger.error("Caught application level error: ",err)
    res.status(500).send("Something went wrong, please try again later");
    // next();
});

app.get('/',(req, res)=>{
    logger.info("Auth-service GET request hit");
    console.log("Value of IP address:", req.ip);
    // console.log("Value of req:", req);
    return res.status(200).json({message:"Welcome to the Auth-service GET Page"});  
});

setupHealthCheckUp(app);

//app routes:
app.use('/api/v1/auth', authRouter);

let server = null 
if(process.env.NODE_ENV!=="test"){
     server = app.listen(process.env.PORT || 5000, "0.0.0.0", () => {
        logger.info(`Auth service running on ${process.env.PORT}`);
    });

    setupGracefulShutDown(server, [
        async()=>await getRedisClient.disconnect(),
        async()=>await pool.end()
    ]);
}
export {app, server};