import { createClient } from "redis";

const redisClient = createClient({
  //need to expose the below props in order to connect to redis server
    username:'default',
    password:'Zs4NBtHYoJvvK8zf9WKOWzg2ShIzvMSB',
    socket:{
        host:'redis-17239.c99.us-east-1-4.ec2.cloud.redislabs.com',
        port:17239
    }
});
let isConnected = false;
async function connectWithRetry(retries = 15, delay = 1000) {
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
    console.log("Inside error, value if error.name\n",error.name );
    await connectWithRetry();
  }
});

export async function getRedisClient() {
  if (!isConnected) {
    console.log('Value of isconnected', isConnected);
    await connectWithRetry();
  }
  return redisClient;
}
