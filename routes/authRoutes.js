import express from "express";
import {
  register,
  login,
  logout,
  refresh,
  passwordForgot,
  passwordReset,
  updateUser,
  getUserById,
  failedLogin,
  validateUserToken
} from "../controllers/authController.js";

const router = express.Router();

// Authentication routes
router.post("/auth/register", register);
router.post("/auth/login", login);
router.post("/auth/logout", logout);
router.post("/auth/refresh", refresh);

// Password routes
router.post("/auth/password/forgot", passwordForgot);
router.post("/auth/password/reset", passwordReset);

// Failed login logging
router.post("/auth/failed-login", failedLogin);

// User profile routes
router.get("/auth/user/:id", getUserById);
router.put("/auth/user/:id", updateUser); // <-- Update user route

// Token validation
router.get("/user/validate-token/:token", validateUserToken);

export default router;
