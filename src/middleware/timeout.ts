import { Request, Response, NextFunction } from 'express';
import logger from '../utils/logger';

export const timeoutMiddleware = (timeout: number = 30000) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const timer = setTimeout(() => {
      if (!res.headersSent) {
        logger.warn('Request timeout', {
          correlationId: req.headers['x-correlation-id'],
          method: req.method,
          url: req.url,
        });
        res.status(408).json({
          error: 'Request Timeout',
          detail: 'The request exceeded the maximum allowed time',
        });
      }
    }, timeout);

    const originalEnd = res.end.bind(res);
    res.end = function (...args: any[]) {
      clearTimeout(timer);
      return originalEnd(...args);
    };

    next();
  };
};
