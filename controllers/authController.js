import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import sql from "../db.js";
import { v4 as uuidv4, validate as isUUID } from "uuid";

const generateTokens = (user) => {
  const access_token = jwt.sign(
    { user_id: user.user_id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );

  const refresh_token = jwt.sign(
    { user_id: user.user_id },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: "7d" }
  );

  return { access_token, refresh_token };
};

export const register = async (req, res) => {
  try {
    const { student_id, username, email, password, role } = req.body;

    if (!student_id || !username || !email || !password || !role) {
      return res.status(400).json({
        message: "student_id, username, email, password, and role are required",
      });
    }

    const existingUser = await sql`
      SELECT * FROM tbl_authentication_users 
      WHERE student_id = ${student_id} 
         OR username = ${username} 
         OR email = ${email}
    `;

    if (existingUser.length) {
      return res.status(409).json({
        message: "Student ID, username, or email already exists",
      });
    }

    const password_hash = await bcrypt.hash(password, 10);
    const user_id = uuidv4();

    const user = await sql`
      INSERT INTO tbl_authentication_users(
        user_id, student_id, username, email, password_hash, role, created_at, updated_at
      )
      VALUES(
        ${user_id}, ${student_id}, ${username}, ${email}, ${password_hash}, ${role}, NOW(), NOW()
      )
      RETURNING *
    `;

    res.status(201).json({
      user_id: user[0].user_id,
      student_id: user[0].student_id,
      username: user[0].username,
      email: user[0].email,
      role: user[0].role,
      created_at: user[0].created_at,
      updated_at: user[0].updated_at,
    });

  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const users = await sql`
      SELECT * FROM tbl_authentication_users WHERE email = ${email}
    `;

    if (!users.length) {
      return res.status(404).json({ message: "User not found" });
    }

    const user = users[0];
    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      // FIX: add id column (UUID)
      await sql`
        INSERT INTO tbl_authentication_failed_login(
          id, user_id, attempt_time, ip_address
        )
        VALUES(
          ${uuidv4()}, ${user.user_id}, NOW(), ${req.ip}
        )
      `;
      return res.status(401).json({ message: "Incorrect password" });
    }

    const token = jwt.sign(
      { user_id: user.user_id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      token,
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      user_id: user.user_id,
      role: user.role,
    });

  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

export const logout = async (req, res) => {
  res.json({ message: "Logout successful" });
};

export const getUserById = async (req, res) => {
  try {
    const { id } = req.params;

    // FIX: UUID validation
    if (!isUUID(id)) {
      return res.status(400).json({ message: "Invalid user ID (must be UUID)." });
    }

    const users = await sql`
      SELECT 
        u.user_id,
        u.student_id,
        u.username,
        u.email,
        u.role,
        u.created_at,
        u.updated_at,
        p.first_name,
        p.last_name,
        p.address,
        p.contact_number,
        p.birthdate,
        p.tuition_beneficiary_status
      FROM tbl_authentication_users u
      LEFT JOIN tbl_authentication_user_profiles p 
        ON u.user_id = p.user_id
      WHERE u.user_id = ${id}
    `;

    if (users.length === 0) {
      return res.status(404).json({ message: "User not found." });
    }

    res.json(users[0]);

  } catch (error) {
    console.error("Error getting user by ID:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};

export const updateUser = async (req, res) => {
  try {
    const { id } = req.params;

    // FIX: UUID validation
    if (!isUUID(id)) {
      return res.status(400).json({ message: "Invalid user ID." });
    }

    const {
      first_name,
      last_name,
      address,
      contact_number,
      birthdate,
      tuition_beneficiary_status,
    } = req.body;

    const existingUser = await sql`
      SELECT user_id FROM tbl_authentication_users WHERE user_id = ${id}
    `;

    if (!existingUser.length) {
      return res.status(404).json({ message: "User not found." });
    }

    const profile = await sql`
      INSERT INTO tbl_authentication_user_profiles (
        user_id, first_name, last_name, address, contact_number, birthdate, tuition_beneficiary_status
      )
      VALUES (
        ${id}, ${first_name || null}, ${last_name || null}, ${address || null},
        ${contact_number || null}, ${birthdate || null},
        ${tuition_beneficiary_status ?? false}
      )
      ON CONFLICT (user_id)
      DO UPDATE SET
        first_name = EXCLUDED.first_name,
        last_name = EXCLUDED.last_name,
        address = EXCLUDED.address,
        contact_number = EXCLUDED.contact_number,
        birthdate = EXCLUDED.birthdate,
        tuition_beneficiary_status = EXCLUDED.tuition_beneficiary_status
      RETURNING *;
    `;

    res.json({
      message: "User profile updated successfully.",
      profile: profile[0],
    });

  } catch (error) {
    console.error("Error updating user profile:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};

export const refresh = async (req, res) => {
  res.json({
    access_token: "newAccessToken456",
    expires_at: new Date(Date.now() + 3600000).toISOString(),
    user_id: 1,
    role: "student",
  });
};

export const passwordForgot = async (req, res) => {
  const { email } = req.body;
  res.json({
    message: "Password reset token sent to email",
    reset_token: "reset123abc",
    expires_at: new Date(Date.now() + 3600000).toISOString(),
  });
};

export const passwordReset = async (req, res) => {
  const { user_id, reset_token, expires_at } = req.body;
  res.json({
    reset_id: 1,
    user_id,
    reset_token,
    expires_at,
    created_at: new Date().toISOString(),
  });
};

export const failedLogin = async (req, res) => {
  const { user_id, attempt_time, ip_address } = req.body;

  res.json({
    id: uuidv4(),
    user_id,
    attempt_time,
    ip_address,
  });
};

export const validateUserToken = (req, res) => {
  res.json({
    valid: true,
    user_id: 1,
    role: "student",
    expires_at: new Date(Date.now() + 3600000).toISOString(),
  });
};
