import { Request, Response } from "express";
import logger from "../config/logger";

export const Register = async (req: Request, res: Response) => {
    logger.info('Register')
    res.status(200).send({
        message: "Please register"
    })
}