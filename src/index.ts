require('dotenv').config();

import logger from './config/logger';
import express from 'express';
import cors from 'cors';
import routes from './routes';
import cookieParser from 'cookie-parser';
import { ValidationMiddleware } from './middleware/validation.middleware';
import MongoConfig from './config/db.config';

MongoConfig();

const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(ValidationMiddleware);
app.use(cors({
    credentials: true,
    origin: [`${process.env.CORS_ORIGIN}`]
}));

routes(app);

app.listen(8000, () => {
    logger.info('Server listening on port 8000');
});
