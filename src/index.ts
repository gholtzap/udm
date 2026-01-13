import dotenv from 'dotenv';
dotenv.config();

import express, { Request, Response } from 'express';
import { initializeMongoDB } from './db/mongodb';
import { authRateLimiter } from './middleware/rate-limit';
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

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.get('/health', (req: Request, res: Response) => {
  res.json({ status: 'ok' });
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

const startServer = async () => {
  try {
    await initializeMongoDB();
    console.log('MongoDB connected successfully');
    console.log('Rate limiting enabled for authentication endpoints (nudm-ueau)');

    app.listen(PORT, () => {
      console.log(`nUDM server is running on port ${PORT}`);
    });
  } catch (error) {
    console.error('Failed to connect to MongoDB:', error);
    process.exit(1);
  }
};

startServer();
