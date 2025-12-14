import { neon } from "@neondatabase/serverless";
import dotenv from "dotenv";

dotenv.config();

function cleanDatabaseUrl(url) {
  if (!url) return null;

  return url.replace(/(&?channel_binding=require)/g, "");
}

const DATABASE_URL = cleanDatabaseUrl(process.env.DATABASE_URL);

if (!DATABASE_URL) {
  console.error("❌ ERROR: DATABASE_URL is missing in .env");
  process.exit(1);
}

const sql = neon(DATABASE_URL);

(async () => {
  try {
    await sql`SELECT 1`;
    console.log("✅ Connected to Neon database successfully!");
  } catch (error) {
    console.error("❌ Failed to connect to Neon:");
    console.error(error);
  }
})();

export default sql;
