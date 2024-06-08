import JWT from 'jsonwebtoken';
import createError from 'http-errors';
import dotenv from 'dotenv';
import userModel from '../models/user.model.js';
dotenv.config();

export const signAccessToken = (user) => {
    return new Promise((resolve, reject) => {
        const payload = {
            aud: user.id,
        };
        const secret = process.env.ACCESS_TOKEN_SECRET;
        const options = {
            expiresIn: process.env.JWT_ACCESS_TOKEN_EXPIRE,
        };
        JWT.sign(payload, secret, options, (error, token) => {
            if (error) return reject(error);
            resolve(token);
        });
    });
};

export const verifyAccessToken = async (req, res, next) => {
    try {
        const { authorization } = req.headers;
        if (!authorization) return next(createError.Unauthorized("Please Login to access this resource"));
        const token = authorization.split(' ')[1];
        JWT.verify(token, process.env.ACCESS_TOKEN_SECRET, (error, payload) => {
            if (error) {
                if (error.name === 'TokenExpiredError') return next(createError.Unauthorized("Session expired. Please login again"));
                return next(createError.Unauthorized("Invalid token"));
            }
            req.user = { id: payload.aud };
            next();
        });
    } catch (error) {
        console.log(error);
        next(createError.InternalServerError());
    }
};


export const authorizeRoles = (...roles) => {
    return async(req, res, next) => {
        try {
            req.user = await userModel.findById(req.user.id);
            if(!req.user.role) return next(createError.Unauthorized("Please Login to access this resource"));
            if (!roles.includes(req.user.role)) return next(createError.Forbidden(`${req.user.role} is not allowed to access this resource`));
            next();
        } catch (error) {
            console.log(error);
            next(createError.InternalServerError());
        }
    };
};
