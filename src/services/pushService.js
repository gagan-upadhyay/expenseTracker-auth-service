import webpush from 'web-push';

const PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY || '';
const PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || '';
const CONTACT = process.env.VAPID_CONTACT || 'mailto:security@example.com';

if (PUBLIC_KEY && PRIVATE_KEY) {
  try {
    webpush.setVapidDetails(CONTACT, PUBLIC_KEY, PRIVATE_KEY);
  } catch (err) {
    console.error('[pushService] Failed to set VAPID details:', err);
  }
} else {
  console.warn('[pushService] VAPID keys not configured; push notifications disabled');
}

const sendNotification = async (subscription, payload) => {
  try {
    await webpush.sendNotification(subscription, JSON.stringify(payload));
    return true;
  } catch (err) {
    console.error('[pushService] sendNotification error:', err);
    throw err;
  }
};

export { sendNotification, webpush };
