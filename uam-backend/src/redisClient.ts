import Redis from 'ioredis';
import type { RedisOptions } from 'ioredis';

function createRedisClient() {
  const redisUrl = process.env.REDIS_URL;

  // If REDIS_URL is provided (Upstash style), use it directly
  if (redisUrl) {
    const client = new Redis(redisUrl, {
      maxRetriesPerRequest: parseInt(process.env.REDIS_MAX_RETRIES_PER_REQUEST || '3', 10),
      retryStrategy: (times: number) => Math.min(times * 200, 5_000),
      connectTimeout: parseInt(process.env.REDIS_CONNECT_TIMEOUT_MS || '10000', 10),
      commandTimeout: parseInt(process.env.REDIS_COMMAND_TIMEOUT_MS || '5000', 10),
      keepAlive: parseInt(process.env.REDIS_KEEPALIVE_MS || '30000', 10),
    });

    client.on('error', (err: Error) => {
      console.warn('Redis connection error:', err.message);
    });

    client.on('connect', () => {
      console.log('Redis TCP connected');
    });

    client.on('close', () => {
      console.warn('Redis connection closed');
    });

    return client;
  }

  // Fallback: build from individual env vars
  const redisHost = process.env.REDIS_HOST || 'localhost';
  const redisPort = parseInt(process.env.REDIS_PORT || '6379', 10);
  const redisPassword = process.env.REDIS_PASSWORD || '';
  const redisTls = process.env.REDIS_TLS === 'true';
  const redisDb = parseInt(process.env.REDIS_DB || '0', 10);

  const redisOptions: RedisOptions = {
    host: redisHost,
    port: redisPort,
    password: redisPassword || undefined,
    tls: redisTls ? { rejectUnauthorized: true } : undefined,
    db: redisDb,
    maxRetriesPerRequest: parseInt(process.env.REDIS_MAX_RETRIES_PER_REQUEST || '3', 10),
    retryStrategy: (times: number) => Math.min(times * 200, 5_000),
    connectTimeout: parseInt(process.env.REDIS_CONNECT_TIMEOUT_MS || '10000', 10),
    commandTimeout: parseInt(process.env.REDIS_COMMAND_TIMEOUT_MS || '5000', 10),
    keepAlive: parseInt(process.env.REDIS_KEEPALIVE_MS || '30000', 10),
  };

  const primaryRedis = new Redis(redisOptions);

  primaryRedis.on('error', (err: Error) => {
    console.warn('Redis connection error:', err.message);
  });

  primaryRedis.on('connect', () => {
    console.log('Redis TCP connected');
  });

  primaryRedis.on('close', () => {
    console.warn('Redis connection closed');
  });

  return primaryRedis;
}

export default createRedisClient();
export type { RedisOptions };
