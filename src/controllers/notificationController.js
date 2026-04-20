import { sendNotification } from '../services/pushService.js';
import { saveSubscription, deleteSubscription, getSubscription, listSubscriptions, cleanupOldSubscriptions } from '../subscriptionModel.js';

export const subscribe = async (req, res) => {
  try {
    const userId = req.user?.id;
    const subscription = req.body;
    if (!userId) return res.status(401).json({ success: false, message: 'Unauthorized' });
    if (!subscription || !subscription.endpoint) return res.status(400).json({ success: false, message: 'Invalid subscription object' });

    await saveSubscription(userId, subscription);
    return res.status(201).json({ success: true });
  } catch (err) {
    console.error('[notificationController] subscribe error:', err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

export const unsubscribe = async (req, res) => {
  try {
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ success: false, message: 'Unauthorized' });

    await deleteSubscription(userId);
    return res.status(200).json({ success: true });
  } catch (err) {
    console.error('[notificationController] unsubscribe error:', err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

export const sendTest = async (req, res) => {
  try {
    const targetUser = req.body.userId || req.user?.id;
    if (!targetUser) return res.status(400).json({ success: false, message: 'userId required' });

    const subscription = await getSubscription(targetUser);
    if (!subscription) return res.status(404).json({ success: false, message: 'Subscription not found' });

    const payload = req.body.payload || { title: 'Test Notification', body: 'This is a test notification' };
    await sendNotification(subscription, payload);
    return res.json({ success: true });
  } catch (err) {
    console.error('[notificationController] sendTest error:', err);
    return res.status(500).json({ success: false, message: 'Failed to send notification' });
  }
};

export const listAllSubscriptions = async (req, res) => {
  try {
    const limit = parseInt(req.query.limit || '100', 10);
    const offset = parseInt(req.query.offset || '0', 10);
    const rows = await listSubscriptions(limit, offset);
    return res.json({ success: true, data: rows });
  } catch (err) {
    console.error('[notificationController] listAllSubscriptions error:', err);
    return res.status(500).json({ success: false, message: 'Failed to list subscriptions' });
  }
};

export const cleanupSubscriptions = async (req, res) => {
  try {
    const ttl = parseInt(req.body.ttlDays || process.env.SUBSCRIPTION_TTL_DAYS || '90', 10);
    const deleted = await cleanupOldSubscriptions(ttl);
    return res.json({ success: true, deleted: deleted });
  } catch (err) {
    console.error('[notificationController] cleanupSubscriptions error:', err);
    return res.status(500).json({ success: false, message: 'Failed to cleanup subscriptions' });
  }
};
