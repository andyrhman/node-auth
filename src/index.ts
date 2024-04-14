require('dotenv').config();

import logger from './config/logger';
import express from 'express';
import cors from 'cors';
import routes from './routes';
import cookieParser from 'cookie-parser';
import myDataSource from './config/data-source';
import { ValidationMiddleware } from './middleware/validation.middleware';

const app = express()

app.use(express.json());
app.use(cookieParser());
app.use(ValidationMiddleware);
app.use(cors({
    credentials: true,
    origin: [`${process.env.CORS_ORIGIN}`]
}));

myDataSource.initialize().then(() => {
    routes(app);

    logger.info("Database has been initialized!");
    app.listen(8000, () => {
        logger.info('Server listening on port 8000');
    });
}).catch((err) => {
    logger.error(err);
});
