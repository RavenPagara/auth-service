import jwt from "jsonwebtoken";
import config from "../config.js";
import sql from "../db.js";

export const validateToken = (req, res, next) => {
  try {
    const token = req.params.token;
    const decoded = jwt.verify(token, config.jwtSecret);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
};
