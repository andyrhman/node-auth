import { Request, Response } from "express"
import { Reset } from "../entity/reset.entity";
import { transporter } from "../config/transporter";
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as handlebars from 'handlebars';
import myDataSource from "../config/data-source";
import logger from "../config/logger";

export const Forgot = async (req: Request, res: Response) => {
    try {
        const { email } = req.body;

        // const TOKEN_EXPIRATION = 30 * 60 * 1000; // 30 minutes in milliseconds
        const TOKEN_EXPIRATION = 30 * 1000; // 30 seconds in milliseconds
        const token = crypto.randomBytes(16).toString('hex');
        const tokenExpiresAt = Date.now() + TOKEN_EXPIRATION;

        await myDataSource.getRepository(Reset).save({
            email,
            token,
            expiresAt: tokenExpiresAt
        })

        const url = `http://localhost:3000/reset/${token}`;
        // ? https://www.phind.com/search?cache=lk6d4xezo7ag6qha2hoi70i5
        const source = fs.readFileSync('src/templates/forgot.handlebars', 'utf-8').toString();
        const template = handlebars.compile(source);
        const replacements = {
            name: email,
            url
        };

        const htmlToSend = template(replacements);

        const options = {
            from: 'from@mail.com',
            to: email,
            subject: "Reset Your Password",
            html: htmlToSend
        }

        await transporter.sendMail(options);
        res.send({ message: "Please check your email" });
    } catch (error) {
        logger.error(error.message);
        return res.status(500).send({ message: error.message })
    }

}