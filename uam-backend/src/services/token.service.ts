import jwt, { SignOptions } from 'jsonwebtoken';
import crypto from 'crypto';
import { config } from '../config';
import { IUser } from '../models/User';

interface TokenPayload {
    userId: string;
    sub?: string;
    email: string;
    type: 'access' | 'refresh';
    home_region?: string;
    jti?: string;
    /** Gateway contract: must match Redis `gateway:user:tv:{sub}`. */
    tv?: number;
}

// Parse expiration time string to seconds
const parseExpiry = (expiry: string): number => {
    const match = expiry.match(/^(\d+)([smhd])$/);
    if (!match) return 900; // default 15m
    const value = parseInt(match[1], 10);
    const unit = match[2];
    switch (unit) {
        case 's': return value;
        case 'm': return value * 60;
        case 'h': return value * 3600;
        case 'd': return value * 86400;
        default: return 900;
    }
};

export const generateAccessToken = (user: IUser): string => {
    const payload: TokenPayload = {
        userId: user._id.toString(),
        // Gateway contract: `sub` is the authenticated principal.
        sub: user._id.toString(),
        email: user.email,
        type: 'access',
        // Gateway data-residency routing. The auth service can later persist
        // this per user; until then, use an explicit deployment default.
        home_region: config.security.defaultHomeRegion,
        jti: crypto.randomUUID(),
        tv: user.tokenVersion ?? 0,
    };

    const options: SignOptions = {
        expiresIn: parseExpiry(config.jwt.accessExpiresIn),
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
    };

    return jwt.sign(payload, config.jwt.accessSecret, options);
};

export const generateRefreshToken = (user: IUser): string => {
    const payload: TokenPayload = {
        userId: user._id.toString(),
        email: user.email,
        type: 'refresh',
        jti: crypto.randomUUID(),
    };

    const options: SignOptions = {
        expiresIn: parseExpiry(config.jwt.refreshExpiresIn),
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
    };

    return jwt.sign(payload, config.jwt.refreshSecret, options);
};

const ACCESS_VERIFY_OPTS: jwt.VerifyOptions = {
    algorithms: ['HS256'],
    issuer: config.jwt.issuer,
    audience: config.jwt.audience,
};

const REFRESH_VERIFY_OPTS: jwt.VerifyOptions = {
    algorithms: ['HS256'],
    issuer: config.jwt.issuer,
    audience: config.jwt.audience,
};

export const verifyAccessToken = (token: string): TokenPayload | null => {
    try {
        const decoded = jwt.verify(token, config.jwt.accessSecret, ACCESS_VERIFY_OPTS) as TokenPayload;
        if (decoded.type !== 'access') return null;
        return decoded;
    } catch {
        return null;
    }
};

export const verifyRefreshToken = (token: string): TokenPayload | null => {
    try {
        const decoded = jwt.verify(token, config.jwt.refreshSecret, REFRESH_VERIFY_OPTS) as TokenPayload;
        if (decoded.type !== 'refresh') return null;
        return decoded;
    } catch {
        return null;
    }
};

export const generateTokenPair = (user: IUser): { accessToken: string; refreshToken: string } => {
    return {
        accessToken: generateAccessToken(user),
        refreshToken: generateRefreshToken(user),
    };
};
