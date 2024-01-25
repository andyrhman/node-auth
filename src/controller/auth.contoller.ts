import { Request, Response } from "express";
import User from "../models/user.schema";
import logger from "../config/logger";
import * as argon2 from 'argon2';
import * as speakeasy from 'speakeasy';
import { sign, verify } from "jsonwebtoken";
import Token from "../models/token.schema";
import { OAuth2Client } from "google-auth-library";
import { isValidObjectId } from "mongoose";

export const Register = async (req: Request, res: Response) => {
    try {
        const body = req.body;

        if (body.password !== body.password_confirm) {
            return res.status(400).send({ message: "Password do not match" })
        }

        if (await User.findOne({ email: body.email.toLowerCase() })) {
            return res.status(400).send({ message: "Email has already exist" })
        }

        if (await User.findOne({ username: body.username.toLowerCase() })) {
            return res.status(400).send({ message: "Username has already exist" })
        }

        const { password, tfa_secret, ...user } = (await User.create({
            first_name: body.first_name,
            last_name: body.last_name,
            username: body.username.toLowerCase(),
            email: body.email.toLowerCase(),
            password: await argon2.hash(body.password)
        })).toObject();

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

        const user = await User.findOne({ username: body.username });

        if (!user) {
            return res.status(400).send({ message: "Invalid Credentials" })
        }

        if (!await argon2.verify(user.password, body.password)) {
            return res.status(400).send({ message: "Invalid Credentials" })
        }

        const shouldRemember = !!req.body.rememberMe;

        if (user.tfa_secret) {
            return res.send({
                id: user.id,
                rememberMe: shouldRemember,
            })
        }

        const secret = speakeasy.generateSecret({
            name: 'My App'
        });

        res.send({
            id: user.id,
            rememberMe: shouldRemember,
            secret: secret.ascii,
            otpauth_url: secret.otpauth_url
        })
    } catch (error) {
        logger.error(error.message)
        return res.status(500).send({ message: error.message })
    }
}

export const TwoFactor = async (req: Request, res: Response) => {
    if (!isValidObjectId(req.body.id)) {
        return res.status(400).send({
            message: "Invalid Credentials"
        })
    }
    try {
        // ? For 2FA auth
        const id = req.body.id;

        const user = await User.findById(id);

        if (!user) {
            return res.status(400).send({
                message: "Invalid Credentials"
            })
        }

        const secret = user.tfa_secret !== '' ? user.tfa_secret : req.body.secret;

        const verified = speakeasy.totp.verify({
            secret,
            encoding: 'ascii',
            token: req.body.code
        });

        if (!verified) {
            return res.status(400).send({
                message: "Invalid Credentials"
            })
        };

        if (user.tfa_secret === '') {
            await User.findByIdAndUpdate(id, { tfa_secret: secret })
        }

        // ? For storing refresh token in the cookie and database
        const accessToken = sign({ id }, process.env.JWT_SECRET_ACCESS, { expiresIn: '30s' });

        const refreshToken = sign({ id }, process.env.JWT_SECRET_REFRESH, { expiresIn: '1w' });

        // Determine the expiration time for the new refresh token based on rememberMe
        const newRefreshTokenExpiration = req.body.rememberMe
            ? new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) // 1 year from now
            : new Date(Date.now() + 24 * 60 * 60 * 1000); // 7 Days

        await Token.create({
            user_id: id,
            token: refreshToken,
            expired_at: newRefreshTokenExpiration
        })

        res.cookie('refresh_token', refreshToken, {
            httpOnly: true,
            expires: newRefreshTokenExpiration
        })

        res.send({
            token: accessToken
        });

    } catch (error) {
        logger.error(error.message)
        return res.status(401).send({
            message: "Unauthenticated"
        })
    }
}

export const AuthenticatedUser = async (req: Request, res: Response) => {
    try {
        // const accessToken = req.headers.authorization.replace('Bearer ', '');
        const accessToken = req.header('Authorization')?.split(' ')[1] || '';

        const payload: any = verify(accessToken, process.env.JWT_SECRET_ACCESS);

        if (!payload) {
            return res.status(401).send({
                message: "Unauthenticated"
            })
        }

        const user = await User.findById(payload.id)

        if (!user) {
            return res.status(401).send({
                message: "Unauthenticated"
            })
        }

        const { password, tfa_secret, ...data } = user.toObject();

        res.send(data);
    } catch (error) {
        logger.error(error.message)
        return res.status(401).send({
            message: "Unauthenticated"
        })
    }
}

export const QR = async (req: Request, res: Response) => {
    try {
        const qrcode = require('qrcode')

        qrcode.toDataURL('otpauth://totp/My%20App?secret=MZZV2SBXIM7USIKRKFCFEUDHIJ2E6V3JJE5U65ZXEU5HGMCRO4TA', (err: any, data: any) => {
            res.send(`<img src="${data}" />`)
        })
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
                message: "Unauthenticated 1"
            })
        }

        const refreshToken = await Token.findOne({
            user_id: payload.id.toString(),
            expired_at: { $gte: new Date() }
        });

        if (!refreshToken) {
            return res.status(401).send({
                message: "Unauthenticated 2"
            })
        }

        const accessToken = sign({ id: payload.id }, process.env.JWT_SECRET_ACCESS, { expiresIn: '30s' });

        res.send({
            token: accessToken
        })
    } catch (error) {
        logger.error(error.message)
        return res.status(401).send({
            message: "Unauthenticated"
        })
    }
}

export const Logout = async (req: Request, res: Response) => {
    await Token.findOneAndDelete({
        token: req.cookies["refresh_token"]
    });

    res.clearCookie('refresh_token');

    // ? Alternative
    /*
        res.cookie('access_token', '', {maxAge: 0});
        res.cookie('refresh_token', '', {maxAge: 0});
    */

    res.status(204).send(null);
}

// Google Auth Logic
async function generateUniqueUsername(proposedUsername) {
    let user = await User.findOne({ username: proposedUsername });
    if (user) {
        // ? If there is existing username inside db, generate a username
        proposedUsername += Math.floor(Math.random() * 1000);
        return generateUniqueUsername(proposedUsername);
    } else {
        // ? If there is no existing username, instead use the payload.given_name
        return proposedUsername;
    }
}
export const GoogleAuth = async (req: Request, res: Response) => {
    // ? Google auth logic
    const { token } = req.body;

    const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

    const ticket = await client.verifyIdToken({
        idToken: token,
        audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();

    if (!payload) {
        return res.status(401).send({
            message: "Unauhtenticated"
        })
    }

    let user = await User.findOne({ email: payload.email });

    let nameArray = payload.name.split(" ");
    let firstName = nameArray[0];
    let lastName = nameArray[1];
    let proposedUsername = payload.given_name.toLowerCase();

    if (!user) {
        proposedUsername = await generateUniqueUsername(proposedUsername);
        user = await User.create({
            first_name: firstName,
            last_name: lastName,
            username: proposedUsername,
            email: payload.email,
            password: await argon2.hash(token)
        })
    }

    // ? For storing refresh token in the cookie and database
    const accessToken = sign({ id: user.id }, process.env.JWT_SECRET_ACCESS, { expiresIn: '30s' });

    const refreshToken = sign({ id: user.id }, process.env.JWT_SECRET_REFRESH, { expiresIn: '1w' });

    // Determine the expiration time for the new refresh token based on rememberMe
    const newRefreshTokenExpiration = req.body.rememberMe
        ? new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) // 1 year from now
        : new Date(Date.now() + 24 * 60 * 60 * 1000); // 30 seconds from now

    await Token.create({
        user_id: user.id,
        token: refreshToken,
        expired_at: newRefreshTokenExpiration
    })

    res.cookie('refresh_token', refreshToken, {
        httpOnly: true,
        expires: newRefreshTokenExpiration
    })

    res.send({
        token: accessToken
    });
}