import { createClient } from "redis";

const redisClient = createClient({
  //need to expose the below props in order to connect to redis server
    username:'default',
    password:'BgKGWLAzOIAnCL2GEDc3viudHPj3MahN',
    socket:{
        host:'redis-14117.c92.us-east-1-3.ec2.redns.redis-cloud.com',
        port:14117
    }
});
// await redisClient.connect();

// redisClient.on('error', err=>console.error('Redis Error:\n', err));

// let isConnected = false;

// async function connectWithRetry(retries=5, delay=1000){
//     for(let attempt=0;attempt<retries;attempt++){
//         try{
//             await redisClient.connect();
//             console.log("Value of isCOnnexted\n", isConnected);
//             isConnected=true;
//             console.log("value of isConnected after \n", isConnected);
//             console.log("✅ Redis connected with retry function");
//             break;
//         }catch(error){
//             if(error instanceof Error)
//                 {if(error.name==='ConnectionTimeoutError'){
//                     console.warn(`⚠️ Redis timeout. Retrying ${attempt}/${retries}...`);
//                     await new Promise((res)=>setTimeout(res, delay*attempt)); //exponential back-off
//                 }else{
//                     console.error("❌ Redis connection failed:", error);
//                     break;
//                 }
//             }
//         }
//     }
// }

// redisClient.on('error', async(error)=>{
//     console.error('Redis client error:\n',error);
//     if(error.name==='ConnectionTimeoutError'){
//         isConnected=false;
//         await connectWithRetry();
//     }
// });


// export default async function getRedisClient() {
//     if(!isConnected){
//         console.log("value of isConnected form async func:\n", isConnected);
//         await connectWithRetry();
//     }
//     return redisClient;
// }

let isConnected = false;
async function connectWithRetry(retries = 5, delay = 1000) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      await redisClient.connect();
      console.log("✅ Redis connected");
      isConnected = true;
      break;
    } catch (error) {
      if (error.name === "ConnectionTimeoutError") {
        console.warn(`⚠️ Redis timeout. Retrying ${attempt}/${retries}...`);
        await new Promise((res) => setTimeout(res, delay * attempt));
      } else {
        console.error("❌ Redis connection failed:", error);
        break;
      }
    }
  }
}

redisClient.on("error", async (error) => {
  console.error("Redis client error:", error);
  if (error.name === "ConnectionTimeoutError") {
    isConnected = false;
    await connectWithRetry();
  }
});

export async function getRedisClient() {
  if (!isConnected) {
    console.log('Value of iscobnnected', isConnected);
    await connectWithRetry();
  }
  return redisClient;
}
