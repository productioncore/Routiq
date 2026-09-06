import { shutdownTelemetry } from './otel'; // must be imported before express (side-effect init)
import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import passport from './config/passport';
import { config } from './config';
import { connectDatabase, disconnectDatabase, pingDatabase } from './config/database';
import { connectRedis, closeRedis, pingRedisCache } from './config/redis';
import authRoutes from './routes/auth.routes';
import migrationRoutes from './routes/migration.routes';
import profileRoutes from './routes/profile.routes';
import { metricsHandler, metricsMiddleware } from './metrics';
import { warnIfInsecurePepper } from './utils/password.util';
import { warnIfInsecureSecrets } from './utils/secrets.util';
import { boot } from './utils/boot';

warnIfInsecurePepper();
warnIfInsecureSecrets();

const app = express();

app.set('trust proxy', 1);

// Extract real client IP from gateway/Cloudflare headers before rate limiting
app.use((req: Request, _res: Response, next: NextFunction) => {
    const forwardedFor = req.headers['x-forwarded-for'];
    const cfConnectingIp = req.headers['cf-connecting-ip'];
    const realIp = req.headers['x-real-ip'];
    const clientIp = (cfConnectingIp as string) ||
                     (realIp as string) ||
                     ((forwardedFor as string)?.split(',')[0]?.trim());
    if (clientIp) {
        (req as any).realIp = clientIp;
    }
    next();
});

function requireMetricsAuth(req: Request, res: Response, next: NextFunction): void {
    const token = config.metricsToken;
    if (!token) {
        next();
        return;
    }

    const auth = req.headers.authorization;
    if (auth !== `Bearer ${token}`) {
        res.status(401).json({ success: false, message: 'Unauthorized' });
        return;
    }
    next();
}

// Probes and metrics scrapers do not send Origin — register before CORS.
app.get('/health', async (_req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

/** Readiness — Postgres pool + Redis cache must answer before accepting traffic (K8s). */
app.get('/ready', async (_req, res) => {
    const dbOk = await pingDatabase();
    const redisRequired = config.redis.enabled;
    const redisOk = redisRequired ? await pingRedisCache() : true;

    if (dbOk && redisOk) {
        res.json({
            status: 'ready',
            postgres: true,
            redis: redisRequired ? true : 'disabled',
            timestamp: new Date().toISOString(),
        });
        return;
    }

    res.status(503).json({
        status: 'not_ready',
        postgres: dbOk,
        redis: redisRequired ? redisOk : 'disabled',
        timestamp: new Date().toISOString(),
    });
});

app.get('/metrics', requireMetricsAuth, metricsHandler);

app.use(
    cors({
        origin: (origin, callback) => {
            if (config.nodeEnv === 'development') {
                return callback(null, true);
            }
            // Non-browser clients (curl, health probes) omit Origin; CORS does not apply to them.
            if (!origin) {
                return callback(null, true);
            }
            const allowedOrigins = [
                'http://localhost:5173',
                'http://127.0.0.1:5173',
                'http://localhost:5174',
                'http://127.0.0.1:5174',
                'http://localhost:3000',
                'http://localhost:8091',
                'http://127.0.0.1:8091',
                config.clientUrl,
            ];
            if (allowedOrigins.indexOf(origin) !== -1) {
                callback(null, true);
            } else {
                callback(new Error('Not allowed by CORS'));
            }
        },
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
        allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin', 'X-CSRF-Token'],
        exposedHeaders: ['Content-Type'],
        preflightContinue: false,
        optionsSuccessStatus: 204,
    }),
);

app.use(
    helmet({
        crossOriginResourcePolicy: { policy: 'cross-origin' },
        crossOriginEmbedderPolicy: false,
    }),
);

app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: true, limit: '64kb' }));
app.use(cookieParser());
app.use(passport.initialize());

app.use(metricsMiddleware);

// ── Request logging (ADR-0060 privacy policy) ────────────────────────────────
// NO client IP, NO User-Agent in logs. Each request prints one visually
// separated block: start line, then completion line with status + latency.
// Errors/exceptions print their message under the END line when status >= 400.
let uamReqSeq = 0;
app.use((req: Request, res: Response, next: NextFunction) => {
    const rid = (req.headers['x-request-id'] as string) || `uam-${++uamReqSeq}`;
    const start = Date.now();
    console.log(`-> ${rid} ${req.method} ${req.originalUrl.split('?')[0]}`);
    res.on('finish', () => {
        const ms = Date.now() - start;
        console.log(`<- ${rid} ${res.statusCode} ${ms}ms`);
    });
    next();
});

app.use('/api/auth', authRoutes);
app.use('/api/auth/migrate', migrationRoutes);
app.use('/api/auth/profile', profileRoutes);

app.use((req, res) => {
    res.status(404).json({ success: false, message: 'Route not found' });
});

app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
    const rid = (req as any)._rid || '-';
    console.log(`└ END ${rid} status=500 exception=${err.name}: ${err.message}`);
    if (config.nodeEnv !== 'production' && err.stack) {
        console.log(err.stack.split('\n').slice(0, 4).join('\n'));
    }
    const isCors = err.message === 'Not allowed by CORS';
    res.status(isCors ? 403 : 500).json({
        success: false,
        message: config.nodeEnv === 'development' && !isCors ? err.message : isCors ? 'Forbidden' : 'Internal server error',
    });
});

const startServer = async (): Promise<void> => {
    try {
        await connectDatabase();
        await connectRedis();

        const server = app.listen(config.port, '0.0.0.0', () => {
            boot.flush();
        });

        const shutdown = async (signal: string) => {
            console.log(`[shutdown] ${signal} received`);
            server.close();
            await closeRedis();
            await disconnectDatabase();
            await shutdownTelemetry();
            process.exit(0);
        };

        process.on('SIGTERM', () => void shutdown('SIGTERM'));
        process.on('SIGINT', () => void shutdown('SIGINT'));
    } catch (error) {
        console.error('[boot] failed to start:', error instanceof Error ? error.message : error);
        process.exit(1);
    }
};

startServer();