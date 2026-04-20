import { ensureTable } from './subscriptionModel.js';

(async () => {
  try {
    await ensureTable();
    console.log('push_subscriptions table ready');
    process.exit(0);
  } catch (err) {
    console.error('Failed to initialize push_subscriptions table:', err);
    process.exit(1);
  }
})();