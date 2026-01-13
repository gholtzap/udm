import rateLimit from 'express-rate-limit';
import { Request, Response } from 'express';

interface RateLimitStore {
  [key: string]: {
    attempts: number;
    failures: number;
    backoffUntil: number | null;
    resetTime: number;
  };
}

const store: RateLimitStore = {};

const BASE_LIMIT = 10;
const WINDOW_MS = 60 * 1000;
const BACKOFF_BASE = 2;
const MAX_BACKOFF_MS = 300 * 1000;

function getIdentifier(req: Request): string {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const supiOrSuci = req.params.supiOrSuci || req.params.supi || req.body?.supiOrSuci;
  return supiOrSuci ? `${ip}:${supiOrSuci}` : ip;
}

function isBackedOff(identifier: string): boolean {
  const record = store[identifier];
  if (!record || !record.backoffUntil) return false;

  if (Date.now() < record.backoffUntil) {
    return true;
  }

  record.backoffUntil = null;
  record.failures = 0;
  return false;
}

function recordFailure(identifier: string): void {
  if (!store[identifier]) {
    store[identifier] = {
      attempts: 0,
      failures: 0,
      backoffUntil: null,
      resetTime: Date.now() + WINDOW_MS,
    };
  }

  const record = store[identifier];
  record.failures += 1;

  const backoffMs = Math.min(
    Math.pow(BACKOFF_BASE, record.failures) * 1000,
    MAX_BACKOFF_MS
  );

  record.backoffUntil = Date.now() + backoffMs;

  console.log(`Rate limit backoff applied for ${identifier}: ${backoffMs}ms (failures: ${record.failures})`);
}

export const authRateLimiter = rateLimit({
  windowMs: WINDOW_MS,
  max: BASE_LIMIT,
  standardHeaders: true,
  legacyHeaders: false,

  keyGenerator: (req: Request) => {
    return getIdentifier(req);
  },

  skip: (req: Request) => {
    const identifier = getIdentifier(req);
    return !isBackedOff(identifier);
  },

  handler: (req: Request, res: Response) => {
    const identifier = getIdentifier(req);
    recordFailure(identifier);

    const record = store[identifier];
    const retryAfter = record.backoffUntil
      ? Math.ceil((record.backoffUntil - Date.now()) / 1000)
      : 60;

    res.status(429).json({
      error: 'Too Many Requests',
      message: 'Rate limit exceeded. Please try again later.',
      retryAfter,
    });
  },

  store: {
    incr: (key: string): Promise<{ totalHits: number; resetTime: Date | undefined }> => {
      if (!store[key]) {
        store[key] = {
          attempts: 0,
          failures: 0,
          backoffUntil: null,
          resetTime: Date.now() + WINDOW_MS,
        };
      }

      const record = store[key];

      if (Date.now() > record.resetTime) {
        record.attempts = 1;
        record.resetTime = Date.now() + WINDOW_MS;
      } else {
        record.attempts += 1;
      }

      return Promise.resolve({
        totalHits: record.attempts,
        resetTime: new Date(record.resetTime),
      });
    },

    decrement: (key: string): Promise<void> => {
      if (store[key]) {
        store[key].attempts = Math.max(0, store[key].attempts - 1);
      }
      return Promise.resolve();
    },

    resetKey: (key: string): Promise<void> => {
      if (store[key]) {
        store[key].attempts = 0;
        store[key].resetTime = Date.now() + WINDOW_MS;
      }
      return Promise.resolve();
    },

    init: (): Promise<void> => Promise.resolve(),
  },
});

setInterval(() => {
  const now = Date.now();
  for (const key in store) {
    const record = store[key];
    if (now > record.resetTime && (!record.backoffUntil || now > record.backoffUntil)) {
      delete store[key];
    }
  }
}, 5 * 60 * 1000);
