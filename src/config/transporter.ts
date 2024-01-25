import { createTransport } from "nodemailer";

export const transporter = createTransport({
    // service: "gmail",
    // host: "smtp.gmail.com",
    // port: 465,
    // secure: true,
    // auth: {
    //     user: process.env.GMAIL_EMAIL,
    //     pass: process.env.GMAIL_PASSWORD,
    // },
    host: '0.0.0.0',
    port: 1025
});