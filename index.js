import express from 'express';
import '@dotenvx/dotenvx/config'
import cors from 'cors';
import compression from 'compression';
import morgan from 'morgan';
import authRouter from './src/routes/AuthRoutes.js';
import {logger} from './config/logger.js';


const app = express();
app.use(express.json())

if(process.eventNames.ENVIRONMENT === 'development'){
    app.use(morgan('dev'));
}

app.use(compression());
app.use((err, req, res, next)=>{
    console.error(err.stack);
    logger.error("Caught application level error: ",err)
    res.status(500).send("Something went wrong, please try again later");
    next();
});
console.log(process.env.CLIENT_PORT);

app.use(cors());

app.get('/',(req, res)=>{
    res.status(200).send("Welcome to the Auth-service GET Page");
    logger.info("Auth-service GET request hit");
})

//app routes:
app.use('/api/v1/auth', authRouter);



app.listen(process.env.PORT,()=>{
    console.log(`Auth service runnig at port ${process.env.PORT}`);
    logger.info(`Auth service running on ${process.env.PORT}`);
});