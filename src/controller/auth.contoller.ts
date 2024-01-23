import { Request, Response } from "express";
import { User } from "../entity/user.entity";
import logger from "../config/logger";
import myDataSource from "../config/data-source";
import * as argon2 from 'argon2'
import { sign, verify } from "jsonwebtoken";

export const Register = async (req: Request, res: Response) => {
    try {
        const body = req.body;
        const repository = myDataSource.getRepository(User);

        if (body.password !== body.password_confirm) {
            return res.status(400).send({ message: "Password do not match" })
        }

        if (await repository.findOne({ where: { email: body.email.toLowerCase() } })) {
            return res.status(400).send({ message: "Email has already exist" })
        }

        const user = await repository.save({
            first_name: body.first_name,
            last_name: body.last_name,
            email: body.email.toLowerCase(),
            password: await argon2.hash(body.password)
        });

        const { password, ...data } = user

        res.status(201).send(data);

    } catch (error) {
        logger.error(error.message)
        return res.status(500).send({
            message: "Invalid Request"
        })
    }
}

export const Login = async (req: Request, res: Response) => {
    try {
        const body = req.body;

        const repository = myDataSource.getRepository(User);

        const user = await repository.findOne({ where: { email: body.email } });

        if (!user) {
            return res.status(400).send({ message: "Invalid Credentials" })
        }

        if (!await argon2.verify(user.password, body.password)) {
            return res.status(400).send({ message: "Invalid Credentials" })
        }

        const accessToken = sign({ id: user.id }, process.env.JWT_SECRET_ACCESS, { expiresIn: '30s' });

        const refreshToken = sign({ id: user.id }, process.env.JWT_SECRET_REFRESH, { expiresIn: '1w' });

        res.cookie('access_token', accessToken, {
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000
        });

        res.cookie('refresh_token', refreshToken, {
            httpOnly: true,
            maxAge: 7 * 24 * 60 * 60 * 1000
        })

        res.send({
            message: "Successfully logged in"
        });
    } catch (error) {
        logger.error(error.message)
        return res.status(500).send({ message: error.message })
    }
}

export const AuthenticatedUser = async (req: Request, res: Response) => {
    try {
        const cookie = req.cookies['access_token'];

        const payload: any = verify(cookie, process.env.JWT_SECRET_ACCESS);

        if (!payload) {
            return res.status(401).send({
                message: "Unauthenticated"
            })
        }

        const user = await myDataSource.getRepository(User).findOne({ where: { id: payload.id } })

        if (!user) {
            return res.status(401).send({
                message: "Unauthenticated"
            })
        }
        const { password, ...data } = user
        res.send(data);
    } catch (error) {
        logger.error(error.message)
        return res.status(400).send({
            message: "Unauthenticated"
        })
    }

}

export const Refresh = async (req: Request, res: Response) => {
    try {
        const cookie = req.cookies['refresh_token'];

        const payload: any = verify(cookie, process.env.JWT_SECRET_REFRESH);

        if (!payload) {
            return res.status(401).send({
                message: "Unauthenticated"
            })
        }

        const accessToken = sign({ id: payload.id }, process.env.JWT_SECRET_ACCESS, { expiresIn: '30s' });

        res.cookie('access_token', accessToken, {
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000
        });

        res.send({
            message: "Success"
        })
    } catch (error) {
        logger.error(error.message)
        return res.status(400).send({
            message: "Unauthenticated"
        })
    }
}

export const Logout = async (req: Request, res: Response) => {

    res.clearCookie('refresh_token');
    res.clearCookie('access_token');

    // ? Alternative
    /* 
        res.cookie('access_token', '', {maxAge: 0});
        res.cookie('refresh_token', '', {maxAge: 0});
    */

    res.status(204).send(null);
}