import express, { type Express } from 'express'
import 'dotenv/config';
import authRoutes from './routes/auth.routes';
import { errorHandler } from './middleware/error.middleware';

const app: Express = express();
app.use(express.json());

app.use('/api/v1/auth', authRoutes);

app.use(errorHandler);

export default app;
