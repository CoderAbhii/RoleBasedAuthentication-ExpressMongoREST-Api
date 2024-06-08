import nodeMailer from "nodemailer";
import dotenv from "dotenv";
dotenv.config();

export const sendEmail = async (options) => {
    const transporter = nodeMailer.createTransport({
        host: process.env.MAIL_SERVICE,
        port: 587,
        secure: false,
        auth: {
            user: process.env.MAIL_USER,
            pass: process.env.MAIL_PASS,
        },
    });
    const mailOptions = {
        from: process.env.MAIL_USER,
        to: options.email,
        subject: options.subject,
        html: options.html,
    };
    await transporter.sendMail(mailOptions);
};