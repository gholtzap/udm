import { Request, Response, NextFunction } from 'express';
import logger from '../utils/logger';

export function requestLoggerMiddleware(req: Request, res: Response, next: NextFunction) {
  const startTime = Date.now();

  res.on('finish', () => {
    const duration = Date.now() - startTime;
    logger.info('Request completed', {
      correlationId: req.correlationId,
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration: `${duration}ms`
    });
  });

  logger.info('Request received', {
    correlationId: req.correlationId,
    method: req.method,
    path: req.path,
    query: req.query
  });

  next();
}
