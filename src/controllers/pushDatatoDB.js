import fs from "fs";
import csv from "csv-parser";
import pkg from "pg";

const { Pool } = pkg;

const pool = new Pool({
  user: "neondb_owner",
  host: "ep-broad-king-a48rk492-pooler.us-east-1.aws.neon.tech",
  database: "ecomDB",
  password: "npg_y8ButJT1kMFo",
  port: 5432,
  sslmode='require',
});

async function startDoing(){

const results = [];

fs.createReadStream("MOCK_DATA.csv")
  .pipe(csv())
  .on("data", (data) => results.push(data))
  .on("end", async () => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      for (const row of results) {
        await client.query(
          `INSERT INTO users 
          (id, firstname, lastname, email, password, auth_type, created_at, theme, base_currency)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
          [
            row.id,
            row.firstname,
            row.lastname,
            row.email,
            row.password,
            row.auth_type,
            row.created_at,
            row.theme,
            row.base_currency,
          ]
        );
      }

      await client.query("COMMIT");
      console.log("Inserted successfully");
    } catch (err) {
      await client.query("ROLLBACK");
      console.error(err);
    } finally {
      client.release();
    }
  });
}

startDoing();