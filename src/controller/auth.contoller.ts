import { Request, Response } from "express";
import { User } from "../entity/user.entity";
import logger from "../config/logger";
import myDataSource from "../config/data-source";
import * as argon2 from 'argon2'
import { sign } from "jsonwebtoken";

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
    const body = req.body;

    const repository = myDataSource.getRepository(User);

    const user = await repository.findOne({ where: { email: body.email } });

    if (!user) {
        return res.status(400).send({ message: "Invalid Credentials" })
    }

    if (!await argon2.verify(user.password, body.password)) {
        return res.status(400).send({ message: "Invalid Credentials" })
    }

    const accessToken = sign({id: user.id}, process.env.JWT_SECRET_ACCESS, {expiresIn: '30s'});

    const refreshToken = sign({id: user.id}, process.env.JWT_SECRET_REFRESH, {expiresIn: '1w'});

    res.cookie('access_token', accessToken, {
        httpOnly: true,
        maxAge: 24 * 60 * 60 & 1000
    });

    res.cookie('refresh_token', refreshToken, {
        httpOnly: true,
        maxAge: 7* 24 * 60 * 60 & 1000
    })

    // const { password, ...data } = user;

    res.send({
        accessToken,
        refreshToken
    });
}