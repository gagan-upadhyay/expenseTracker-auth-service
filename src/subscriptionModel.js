import { pgQuery } from '../config/dbconnection.js';

const ensureTable = async () => {
  const createSQL = `
    CREATE TABLE IF NOT EXISTS push_subscriptions (
      user_id TEXT PRIMARY KEY,
      subscription JSONB NOT NULL,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_push_subscriptions_created_at ON push_subscriptions (created_at);
  `;
  await pgQuery(createSQL);
};

const saveSubscription = async (userId, subscription) => {
  await ensureTable();
  const upsertSQL = `
    INSERT INTO push_subscriptions (user_id, subscription)
    VALUES ($1, $2)
    ON CONFLICT (user_id) DO UPDATE SET subscription = $2, created_at = CURRENT_TIMESTAMP;
  `;
  await pgQuery(upsertSQL, [userId, subscription]);
};

const deleteSubscription = async (userId) => {
  await ensureTable();
  const delSQL = `DELETE FROM push_subscriptions WHERE user_id = $1;`;
  await pgQuery(delSQL, [userId]);
};

const getSubscription = async (userId) => {
  await ensureTable();
  const selSQL = `SELECT subscription FROM push_subscriptions WHERE user_id = $1 LIMIT 1;`;
  const res = await pgQuery(selSQL, [userId]);
  return res.rows[0]?.subscription || null;
};

const listSubscriptions = async (limit = 100, offset = 0) => {
  await ensureTable();
  const selSQL = `SELECT user_id, subscription, created_at FROM push_subscriptions ORDER BY created_at DESC LIMIT $1 OFFSET $2;`;
  const res = await pgQuery(selSQL, [limit, offset]);
  return res.rows;
};

const cleanupOldSubscriptions = async (ttlDays = 90) => {
  await ensureTable();
  const delSQL = `DELETE FROM push_subscriptions WHERE created_at < NOW() - INTERVAL '${ttlDays} days';`;
  const res = await pgQuery(delSQL);
  // pgQuery returns command tag info but not rows for DELETE; return rowCount if available
  return res.rowCount || 0;
};

export { ensureTable, saveSubscription, deleteSubscription, getSubscription, listSubscriptions, cleanupOldSubscriptions };
