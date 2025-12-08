import { neon } from "@neondatabase/serverless";
import dotenv from "dotenv";

dotenv.config();

// --- CLEAN DATABASE_URL (Fixes channel_binding issue) ---
function cleanDatabaseUrl(url) {
  if (!url) return null;

  // Remove the `channel_binding=require` portion if present
  return url.replace(/(&?channel_binding=require)/g, "");
}

// Make a clean URL for Neon
const DATABASE_URL = cleanDatabaseUrl(process.env.DATABASE_URL);

if (!DATABASE_URL) {
  console.error("❌ ERROR: DATABASE_URL is missing in .env");
  process.exit(1);
}

// Initialize Neon client
const sql = neon(DATABASE_URL);

// --- TEST CONNECTION ---
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
