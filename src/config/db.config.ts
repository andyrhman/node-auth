import logger from './logger';
import mongoose from 'mongoose';

const MongoConfig = () => {
    mongoose.connect('mongodb://localhost/node_auth')
        .then(() => logger.info('Database has been initialized!'))
        .catch((err) => logger.error(err));
}

export default MongoConfig;