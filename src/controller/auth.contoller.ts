import { Request, Response } from "express";
import { User } from "../entity/user.entity";
import logger from "../config/logger";
import myDataSource from "../config/data-source";
import * as argon2 from 'argon2'
import * as speakeasy from 'speakeasy'
import { sign, verify } from "jsonwebtoken";
import { Token } from "../entity/token.entity";
import { MoreThanOrEqual } from "typeorm";

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

        const { password, tfa_secret, ...user } = await repository.save({
            first_name: body.first_name,
            last_name: body.last_name,
            email: body.email.toLowerCase(),
            password: await argon2.hash(body.password)
        });

        res.status(201).send(user);

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

        if (user.tfa_secret) {
            return res.send({
                id: user.id
            })
        }

        const secret = speakeasy.generateSecret({
            name: 'My App'
        });

        res.send({
            id: user.id,
            secret: secret.ascii,
            otpauth_url: secret.otpauth_url
        })
    } catch (error) {
        logger.error(error.message)
        return res.status(500).send({ message: error.message })
    }
}

export const AuthenticatedUser = async (req: Request, res: Response) => {
    try {
        // ? alternative --> const accessToken = req.headers.authorization.replace('Bearer ', '');
        const accessToken = req.header('Authorization')?.split(' ')[1] || '';

        const payload: any = verify(accessToken, process.env.JWT_SECRET_ACCESS);

        if (!payload) {
            return res.status(401).send({
                message: "Unauthenticated"
            })
        }

        const { password, tfa_secret, ...user } = await myDataSource.getRepository(User).findOne({ where: { id: payload.id } })

        if (!user) {
            return res.status(401).send({
                message: "Unauthenticated"
            })
        }

        res.send(user);
    } catch (error) {
        logger.error(error.message)
        return res.status(400).send({
            message: "Unauthenticated"
        })
    }

}

export const TwoFactor = async (req: Request, res: Response) => {
    // const accessToken = sign({ id: user.id }, process.env.JWT_SECRET_ACCESS, { expiresIn: '30s' });

    // const refreshToken = sign({ id: user.id }, process.env.JWT_SECRET_REFRESH, { expiresIn: '1w' });

    // const expired_at = new Date()
    // expired_at.setDate(expired_at.getDate() + 7)

    // await myDataSource.getRepository(Token).save({
    //     user_id: user.id,
    //     token: refreshToken,
    //     expired_at
    // })

    // res.cookie('refresh_token', refreshToken, {
    //     httpOnly: true,
    //     maxAge: 7 * 24 * 60 * 60 * 1000
    // })

    // res.send({
    //     token: accessToken
    // });
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

        const refreshToken = await myDataSource.getRepository(Token).findOne({
            where: {
                user_id: payload.id,
                expired_at: MoreThanOrEqual(new Date())
            }
        });

        if (!refreshToken) {
            return res.status(401).send({
                message: "Unauthenticated"
            })
        }

        const accessToken = sign({ id: payload.id }, process.env.JWT_SECRET_ACCESS, { expiresIn: '30s' });

        res.send({
            token: accessToken
        })
    } catch (error) {
        logger.error(error.message)
        return res.status(400).send({
            message: "Unauthenticated"
        })
    }
}

export const Logout = async (req: Request, res: Response) => {
    await myDataSource.getRepository(Token).delete({
        token: req.cookies["refresh_token"]
    })

    res.clearCookie('refresh_token');

    // ? Alternative
    /* 
        res.cookie('access_token', '', {maxAge: 0});
        res.cookie('refresh_token', '', {maxAge: 0});
    */

    res.status(204).send(null);
}