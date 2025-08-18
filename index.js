import express from 'express';
import '@dotenvx/dotenvx/config'
import cors from 'cors';
import compression from 'compression';
import morgan from 'morgan';
import authRouter from './src/routes/AuthRoutes.js';
import {logger} from './config/logger.js';
import cookieParser from 'cookie-parser';


const app = express();
const corsOptions = {
    origin:['http://localhost:3000', 'https://expense-tracker-self-rho-12.vercel.app/'],
    credentials:true
}
app.use(cors(corsOptions));
app.use(express.json())
app.use(cookieParser())


if(process.env.NODE_ENV === 'development'){
    app.use(morgan('dev'));
}

app.use(compression());
app.use((err, req, res, next)=>{
    console.error(err.stack);
    logger.error("Caught application level error: ",err)
    res.status(500).send("Something went wrong, please try again later");
    next();
});

app.get('/',(req, res)=>{
    logger.info("Auth-service GET request hit");
    return res.status(200).send("Welcome to the Auth-service GET Page");
    
})

//app routes:
app.use('/api/v1/auth', authRouter);



app.listen(process.env.PORT,()=>{
    console.log(`Auth service runnig at port ${process.env.PORT}`);
    logger.info(`Auth service running on ${process.env.PORT}`);
});