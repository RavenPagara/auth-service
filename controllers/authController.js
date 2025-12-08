
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import sql from "../db.js";
import { v4 as uuidv4, validate as isUUID } from "uuid";
import config from "../config.js";

const generateTokens = (user) => {
  const access_token = jwt.sign(
    { user_id: user.user_id, role: user.role },
    config.jwtSecret,
    { expiresIn: config.tokenExpiry }
  );

  const refresh_token = jwt.sign(
    { user_id: user.user_id },
    config.jwtRefreshSecret,
    { expiresIn: config.refreshExpiry }
  );

  return { access_token, refresh_token };
};

export const register = async (req, res) => {
  try {
    const { student_id, username, email, password, role } = req.body;

    if (!student_id || !username || !email || !password || !role) {
      return res.status(400).json({ message: "student_id, username, email, password, and role are required" });
    }

    const existingUser = await sql`
      SELECT user_id FROM tbl_authentication_users 
      WHERE student_id = ${student_id} OR username = ${username} OR email = ${email}
    `;

    if (existingUser.length) {
      return res.status(409).json({ message: "Student ID, username, or email already exists" });
    }

    const password_hash = await bcrypt.hash(password, 10);
    const user_id = uuidv4();

    const inserted = await sql`
      INSERT INTO tbl_authentication_users(
        user_id, student_id, username, email, password_hash, role, created_at, updated_at
      )
      VALUES(
        ${user_id}, ${student_id}, ${username}, ${email}, ${password_hash}, ${role}, NOW(), NOW()
      )
      RETURNING *
    `;

    const user = inserted[0];

    res.status(201).json({
      user_id: user.user_id,
      student_id: user.student_id,
      username: user.username,
      email: user.email,
      role: user.role,
      created_at: user.created_at,
      updated_at: user.updated_at,
    });

  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    const users = await sql`SELECT * FROM tbl_authentication_users WHERE email = ${email}`;

    if (!users.length) {
      return res.status(404).json({ message: "User not found" });
    }

    const user = users[0];
    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      // record failed login but only if we have a user_id
      try {
        await sql`
          INSERT INTO tbl_authentication_failed_login (id, user_id, attempt_time, ip_address)
          VALUES (${uuidv4()}, ${user.user_id}, NOW(), ${req.ip})
        `;
      } catch (e) {
        console.warn('Failed to log failed-login:', e.message);
      }
      return res.status(401).json({ message: "Incorrect password" });
    }

    const tokens = generateTokens(user);

    // Optional: save refresh token in auth_tokens table
    try {
      await sql`
        INSERT INTO tbl_authentication_auth_tokens (token_id, user_id, token, expires_at, created_at)
        VALUES (${uuidv4()}, ${user.user_id}, ${tokens.refresh_token}, ${new Date(Date.now() + 7*24*60*60*1000).toISOString()}, NOW())
      `;
    } catch (e) {
      console.warn('Failed to save refresh token:', e.message);
    }

    res.json({
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
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
  // Optional: accept refresh token in body to remove from auth_tokens
  res.json({ message: "Logout successful" });
};

export const getUserById = async (req, res) => {
  try {
    const { id } = req.params;

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
    const { id: user_id } = req.params; // get from route param

    const {
      first_name,
      last_name,
      address,
      contact_number,
      birthdate,
      tuition_beneficiary_status,
    } = req.body;

    // Validate UUID
    if (!isUUID(user_id)) {
      return res.status(400).json({ message: "Valid user_id (UUID) is required in URL." });
    }

    // Check if user exists
    const exists = await sql`SELECT user_id FROM tbl_authentication_users WHERE user_id = ${user_id}`;

    if (exists.length === 0) {
      return res.status(404).json({ message: "User not found." });
    }

    // Make sure booleans handled correctly
    const tuitionFlag = typeof tuition_beneficiary_status === 'boolean' ? tuition_beneficiary_status : (tuition_beneficiary_status ? true : false);

    // INSERT or UPDATE user profile
    const profile = await sql`
      INSERT INTO tbl_authentication_user_profiles (
        user_id, first_name, last_name, address, contact_number, birthdate, tuition_beneficiary_status
      )
      VALUES (
        ${user_id},
        ${first_name || null},
        ${last_name || null},
        ${address || null},
        ${contact_number || null},
        ${birthdate || null},
        ${tuitionFlag}
      )
      ON CONFLICT (user_id)
      DO UPDATE SET
        first_name = COALESCE(EXCLUDED.first_name, tbl_authentication_user_profiles.first_name),
        last_name = COALESCE(EXCLUDED.last_name, tbl_authentication_user_profiles.last_name),
        address = COALESCE(EXCLUDED.address, tbl_authentication_user_profiles.address),
        contact_number = COALESCE(EXCLUDED.contact_number, tbl_authentication_user_profiles.contact_number),
        birthdate = COALESCE(EXCLUDED.birthdate, tbl_authentication_user_profiles.birthdate),
        tuition_beneficiary_status = EXCLUDED.tuition_beneficiary_status
      RETURNING *;
    `;

    return res.status(200).json({ message: "Profile updated successfully.", data: profile[0] });

  } catch (error) {
    console.error("Error updating user profile:", error);
    res.status(500).json({ message: "Internal server error while updating profile", error: error.message });
  }
};

export const refresh = async (req, res) => {
  // Implement real refresh logic if you store refresh tokens; placeholder kept
  res.json({ access_token: "newAccessToken456", expires_at: new Date(Date.now() + 3600000).toISOString(), user_id: 1, role: "student" });
};

export const passwordForgot = async (req, res) => {
  const { email } = req.body;
  // implement real flow: generate token, save to tbl_authentication_password_resets and mail
  res.json({ message: "Password reset token sent to email", reset_token: "reset123abc", expires_at: new Date(Date.now() + 3600000).toISOString() });
};

export const passwordReset = async (req, res) => {
  const { user_id, reset_token, expires_at } = req.body;
  // implement reset validation
  res.json({ reset_id: 1, user_id, reset_token, expires_at, created_at: new Date().toISOString() });
};

export const failedLogin = async (req, res) => {
  const { user_id, attempt_time, ip_address } = req.body;
  // store a record if user_id is valid UUID
  try {
    const id = uuidv4();
    await sql`INSERT INTO tbl_authentication_failed_login (id, user_id, attempt_time, ip_address) VALUES (${id}, ${isUUID(user_id) ? user_id : null}, ${attempt_time || new Date().toISOString()}, ${ip_address || null})`;
    res.json({ id, user_id, attempt_time, ip_address });
  } catch (e) {
    console.error('failedLogin error:', e.message);
    res.status(500).json({ message: 'Failed to record failed login' });
  }
};

export const validateUserToken = (req, res) => {
  res.json({ valid: true, user_id: 1, role: "student", expires_at: new Date(Date.now() + 3600000).toISOString() });
};

