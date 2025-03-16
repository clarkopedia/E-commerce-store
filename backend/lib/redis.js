import Redis from "ioredis"
import dotenv from "dotenv"

dotenv.config()

export const redis = new Redis(process.env.UPSTASH_REDIS_URL);

// redis is a key-value store, its like a giant json store
// await redis.set('foo', 'bar');