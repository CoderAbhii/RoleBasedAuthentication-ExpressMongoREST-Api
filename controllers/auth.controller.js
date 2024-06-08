import createError from "http-errors"
import userModel from "../models/user.model.js";
import bcrypt from "bcryptjs"
import moment from "moment";
import { signAccessToken } from "../utils/jwt.config.js";
import crypto from 'crypto';
import { sendEmail } from "../utils/nodemailer.config.js";
import ejs from "ejs";
import path, { dirname } from 'path';
import { fileURLToPath } from 'url';

/**
 * @DESC Register A User Controller
 */
export const registerUserController = async (req, res, next) => {
    try {
        const { name, email, password } = req.body;
        const checkUserIsExist = await userModel.findOne({ email });
        if (checkUserIsExist) return next(createError.Conflict("User already exists with this email"));
        const hashedPassword = await bcrypt.hash(password, 10);
        const registerUser = new userModel({ name, email, password: hashedPassword });
        const savedUser = await registerUser.save();
        const userRegisterDateTime = moment(savedUser.createdAt).format('MMMM Do YYYY, h:mm:ss a');
        const accessToken = await signAccessToken(savedUser);
        res.status(201).json({ userRegisterDateTime, accessToken });
    } catch (error) {
        console.log(error);
        next(createError.InternalServerError());
    }
}


/**
 * @DESC Login A User Controller
 */
export const loginUserController = async (req, res, next) => {
    try {
        const { email, password } = req.body;
        const checkUser = await userModel.findOne({ email }).select("+password");
        if (!checkUser) return next(createError.NotFound('Credentials not found'));

        const checkPassword = await bcrypt.compare(password, checkUser.password);
        if (!checkPassword) return next(createError.NotFound('Credentials not found'));

        const userLoginDateTime = moment().format('MMMM Do YYYY, h:mm:ss a');
        const accessToken = await signAccessToken(checkUser);
        res.json({ userLoginDateTime, accessToken });

    } catch (error) {
        console.log(error);
        next(createError.InternalServerError());
    }
}


/**
 * @DESC Get Logged In User Controller
 */
export const getLoggedInUserController = async (req, res, next) => {
    try {
        const userId = req.user.id;
        const user = await userModel.findById(userId);
        if (!user) return next(createError.NotFound('User not found'));
        res.json({ user });
    } catch (error) {
        console.log(error);
        next(createError.InternalServerError());
    }
}


/**
 * @DESC Forgot Password Controller
 */
export const forgotPasswordController = async (req, res, next) => {
    try {
        const { email } = req.body;
        const checkEmailOfUser = await userModel.findOne({ email });
        if (!checkEmailOfUser) return next(createError.NotFound('Email not found'));
        const resetToken = crypto.randomBytes(20).toString("hex");
        checkEmailOfUser.resetPasswordToken = crypto.createHash("sha256").update(resetToken).digest("hex");
        checkEmailOfUser.resetPasswordExpire = Date.now() + 5 * 60 * 1000;
        await checkEmailOfUser.save();
        const resetPasswordUrl = `http://localhost:5000/api/v1/auth/password/reset/${resetToken}`;
        const __dirname = dirname(fileURLToPath(import.meta.url));
        const emailTemplateFile = path.resolve(__dirname, '..');
        const templatePath = path.join(emailTemplateFile, 'views', 'resetPasswordTemplate.ejs');
        const htmlContent = await ejs.renderFile(templatePath, { resetPasswordUrl });
        try {
            await sendEmail({
                email: checkEmailOfUser.email,
                subject: `Rolebased Authentication Password Recovery Email`,
                html: htmlContent
            });
            res.json({
                message: `We have sent you a password reset email in ${checkEmailOfUser.email} successfully`
            })
        } catch (error) {
            checkEmailOfUser.resetPasswordToken = undefined;
            checkEmailOfUser.resetPasswordExpire = undefined;
            await checkEmailOfUser.save();
        }
    } catch (error) {
        console.log(error);
        next(createError.InternalServerError());
    }
}


/**
 * @DESC Reset Password Controller
 */
export const resetPasswordController = async (req, res, next) => {
    try {
        const { password, confirmPassword } = req.body;
        const resetPasswordToken = crypto.createHash("sha256").update(req.params.token).digest("hex");
        const user = await userModel.findOne({
            resetPasswordToken,
            resetPasswordExpire: { $gt: Date.now() },
        });
        if (!user) return next(createError.Unauthorized("Your password reset link is expired. Try again"));
        if (password !== confirmPassword) return next(createError.BadRequest("Password doesn't matched"));
        const hashedPassword = await bcrypt.hash(password, 10);
        user.password = hashedPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpire = undefined;
        await user.save();
        res.status(200).json({ message: "Password Reset Successfully" });
    } catch (error) {
        console.log(error);
        next(createError.InternalServerError());
    }
}


/**
 * @DESC Password Update Controller
 */
export const passwordUpdateController = async (req, res, next) => {
    try {
        const userId = req.user.id;
        const { oldPassword, newPassword, confirmPassword } = req.body;
        const user = await userModel.findById(userId).select("+password");

        if (!user) return next(createError.BadRequest('Something went wrong. Please try again.'));

        const checkPassword = await bcrypt.compare(oldPassword, user.password);
        if (!checkPassword) return next(createError.BadRequest('Old password not verified'));
        if (newPassword !== confirmPassword) return next(createError.BadRequest("Password doesn't matched"));

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        await user.save();
        res.status(200).json({ message: "Password Update Successfully" });
    } catch (error) {
        console.log(error);
        next(createError.InternalServerError());
    }
}


/**
 * @DESC Profile Update Controller
 */
export const profileUpdateController = async (req, res, next) => {
    try {
        const userId = req.user.id;
        const { name, email } = req.body;

        if (!name || !email) return next(createError.BadRequest('Name and email are required'));
        const existingUser = await userModel.findOne({ email });
        if (existingUser && existingUser.id !== userId) return next(createError.Conflict('Email is already in use'));

        const newUserData = { name, email };

        const updatedUser = await userModel.findByIdAndUpdate(userId, newUserData, { new: true });

        if (!updatedUser) return next(createError.NotFound('User not found'));

        res.json({ message: "Profile updated successfully" });
    } catch (error) {
        console.log(error);
        next(createError.InternalServerError());
    }
};


/**
 * @DESC Check All Users Controller || <{Admin Access Route}>
 */
export const getAllUsersController = async (req, res, next) => {
    try {
        const allUsers = await userModel.find();
        res.json({ allUsers });
    } catch (error) {
        console.log(error);
        next(createError.InternalServerError());
    }
}


/**
 * @DESC Check Single User Controller || <{Admin Access Route}>
 */
export const getSingleUserController = async (req, res, next) => {
    try {
        const userId = req.params.id;
        const user = await userModel.findById(userId);
        res.json({ user });
    } catch (error) {
        console.log(error);
        next(createError.InternalServerError());
    }
}


/**
 * @DESC Update Single User Controller || <{Admin Access Route}>
 */
export const updateUserController = async (req, res, next) => {
    try {
        const { name, email, role } = req.body;
        const existingUser = await userModel.findOne({ email });
        if (existingUser) return next(createError.Conflict('Email is already in use'));
        const newUserData = { name, email, role }
        const user = await userModel.findByIdAndUpdate(req.params.id, newUserData, { new: true, runValidators: true, });
        res.json({ message: "Profile update successfully" });
    } catch (error) {
        console.log(error);
        next(createError.InternalServerError());
    }
}


/**
 * @DESC Delete User Controller || <{Admin Access Route}>
 */
export const deleteUserController = async (req, res, next) => {
    try {
        const user = await userModel.findByIdAndDelete(req.params.id);
        if (!user) return next(createError.NotFound('User not found'));
        res.json({ message: "User deleted successfully" });
    } catch (error) {
        console.log(error);
        next(createError.InternalServerError());
    }
}