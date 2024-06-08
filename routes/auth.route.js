import express from 'express';
import { deleteUserController, forgotPasswordController, getAllUsersController, getLoggedInUserController, getSingleUserController, loginUserController, passwordUpdateController, profileUpdateController, registerUserController, resetPasswordController, updateUserController } from '../controllers/auth.controller.js';
import { loginUserValidation, registerUserValidation } from '../validation/user.validation.js';
import { handleValidationErrors } from '../middlewares/validation.middleware.js';
import { authorizeRoles, verifyAccessToken } from '../utils/jwt.config.js';
const router = express.Router();

router.post('/register', registerUserValidation, handleValidationErrors, registerUserController);

router.post('/login', loginUserValidation, handleValidationErrors, loginUserController);

router.get('/my-account', verifyAccessToken, getLoggedInUserController);

router.post('/password/forgot', forgotPasswordController);

router.put('/password/reset/:token', resetPasswordController);

router.put('/password/update', verifyAccessToken, passwordUpdateController);

router.put('/myaccount/update', verifyAccessToken, profileUpdateController);

router.get('/admin/users', verifyAccessToken, authorizeRoles('Admin'), getAllUsersController);

router.get('/admin/user/:id', verifyAccessToken,  authorizeRoles("Admin"), getSingleUserController);

router.put('/admin/account/update/:id', verifyAccessToken,  authorizeRoles("Admin"), updateUserController);

router.delete('/admin/user/delete/:id', verifyAccessToken,  authorizeRoles("Admin"), deleteUserController);

export default router;