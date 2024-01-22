import { ValidationError } from 'class-validator';
import express from 'express';

export const ValidationMiddleware = (err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (Array.isArray(err) && err[0] instanceof ValidationError) {
        const formattedErrors = err.map(e => {
            const constraints = e.constraints;
            const messages = constraints ? Object.values(constraints) : [];
            return { message: messages[0] }; // This will return only the first error message
        });

        // Filter out undefined messages if any field did not have a constraint violation
        const errorMessages = formattedErrors.filter(e => e.message).map(e => e.message);

        return res.status(400).json({ errors: errorMessages });
    }

    // If it's not a validation error, just pass it on
    return next(err);
}