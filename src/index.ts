import dotenv from 'dotenv';
dotenv.config();

import express, { Request, Response } from 'express';
import { initializeMongoDB, closeConnection, getDatabase } from './db/mongodb';
import { authRateLimiter } from './middleware/rate-limit';
import { correlationIdMiddleware } from './middleware/correlation-id';
import { requestLoggerMiddleware } from './middleware/request-logger';
import { timeoutMiddleware } from './middleware/timeout';
import eeRouter from './routers/nudm-ee';
import mtRouter from './routers/nudm-mt';
import niddauRouter from './routers/nudm-niddau';
import ppRouter from './routers/nudm-pp';
import rsdsRouter from './routers/nudm-rsds';
import sdmRouter from './routers/nudm-sdm';
import ssauRouter from './routers/nudm-ssau';
import ueauRouter from './routers/nudm-ueau';
import uecmRouter from './routers/nudm-uecm';
import ueidRouter from './routers/nudm-ueid';
import { Server } from 'http';
import logger from './utils/logger';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '10mb' }));
app.use(timeoutMiddleware(30000));
app.use(correlationIdMiddleware);
app.use(requestLoggerMiddleware);

app.get('/health', async (_req: Request, res: Response) => {
  try {
    await getDatabase().admin().ping();
    res.json({ status: 'ok' });
  } catch (err) {
    res.status(503).json({ status: 'error', detail: 'Database unavailable' });
  }
});

app.use('/nudm-ee/v1', eeRouter);
app.use('/nudm-mt/v1', mtRouter);
app.use('/nudm-niddau/v1', niddauRouter);
app.use('/nudm-pp/v1', ppRouter);
app.use('/nudm-rsds/v1', rsdsRouter);
app.use('/nudm-sdm/v2', sdmRouter);
app.use('/nudm-ssau/v1', ssauRouter);
app.use('/nudm-ueau/v1', authRateLimiter, ueauRouter);
app.use('/nudm-uecm/v1', uecmRouter);
app.use('/nudm-ueid/v1', ueidRouter);

let server: Server;

const gracefulShutdown = async (signal: string) => {
  logger.info(`${signal} received, starting graceful shutdown...`);

  if (server) {
    server.close(async () => {
      logger.info('HTTP server closed');

      try {
        await closeConnection();
        logger.info('MongoDB connection closed');
        process.exit(0);
      } catch (error) {
        logger.error('Error closing MongoDB connection:', { error });
        process.exit(1);
      }
    });

    setTimeout(() => {
      logger.error('Forced shutdown after timeout');
      process.exit(1);
    }, 30000);
  } else {
    process.exit(0);
  }
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

const startServer = async () => {
  try {
    await initializeMongoDB();
    logger.info('MongoDB connected successfully');
    logger.info('Rate limiting enabled for authentication endpoints (nudm-ueau)');

    server = app.listen(PORT, () => {
      logger.info(`nUDM server is running on port ${PORT}`);
    });
  } catch (error) {
    logger.error('Failed to connect to MongoDB:', { error });
    process.exit(1);
  }
};

startServer();
