import { neon } from "@neondatabase/serverless";
import dotenv from "dotenv";

dotenv.config();

// Create a Neon connection instance
const sql = neon(process.env.DATABASE_URL);

export default sql;
