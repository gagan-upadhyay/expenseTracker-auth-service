import { getMessaging } from '../config/firebaseAdmin.js';
import { logger } from '../config/logger.js';

/**
 * Send a notification to a specific device using FCM token
 * @param {string} token - FCM device token
 * @param {object} options - Notification options
 * @param {string} options.title - Notification title
 * @param {string} options.body - Notification body
 * @param {object} options.data - Optional data payload
 * @returns {Promise<string>} - Message ID
 */
export const sendNotification = async (token, options) => {
  try {
    if (!token) {
      logger.warn('FCM token is missing');
      return null;
    }

    const messaging = getMessaging();
    if (!messaging) {
      logger.warn('FCM not initialized - skipping notification');
      return null;
    }

    const message = {
      notification: {
        title: options.title || 'Notification',
        body: options.body || '',
      },
      data: options.data || {},
      token: token.trim(),
    };

    const response = await messaging.send(message);

    logger.info(`FCM notification sent successfully: ${response}`);
    return response;
  } catch (error) {
    logger.error('Error sending FCM notification:', error);
    throw error;
  }
};

/**
 * Send a notification to multiple devices
 * @param {string[]} tokens - Array of FCM device tokens
 * @param {object} options - Notification options
 * @returns {Promise<object>} - Results object with success and failure counts
 */
export const sendMulticastNotification = async (tokens, options) => {
  try {
    if (!tokens || tokens.length === 0) {
      logger.warn('No FCM tokens provided for multicast');
      return { successCount: 0, failureCount: 0 };
    }

    const message = {
      notification: {
        title: options.title || 'Notification',
        body: options.body || '',
      },
      data: options.data || {},
    };

    const messaging = getMessaging();
    const response = await messaging.sendMulticast({
      ...message,
      tokens: tokens.map(token => token.trim()),
    });

    logger.info(`FCM multicast sent: ${response.successCount} successful, ${response.failureCount} failed`);
    return response;
  } catch (error) {
    logger.error('Error sending multicast FCM notification:', error);
    throw error;
  }
};

/**
 * Send notification on login event
 * @param {string} token - FCM device token
 * @param {object} userData - User information
 * @returns {Promise<string|null>} - Message ID or null
 */
export const sendLoginNotification = async (token, userData) => {
  return sendNotification(token, {
    title: 'Login Successful',
    body: `Welcome back ${userData.firstname || 'User'}! You have successfully logged in.`,
    data: {
      type: 'login',
      userId: userData.id,
      timestamp: new Date().toISOString(),
    },
  });
};

/**
 * Send notification on logout event
 * @param {string} token - FCM device token
 * @param {object} userData - User information
 * @returns {Promise<string|null>} - Message ID or null
 */
export const sendLogoutNotification = async (token, userData) => {
  return sendNotification(token, {
    title: 'Logged Out',
    body: `You have been logged out. See you next time!`,
    data: {
      type: 'logout',
      userId: userData.id,
      timestamp: new Date().toISOString(),
    },
  });
};

/**
 * Send security alert notification
 * @param {string} token - FCM device token
 * @param {string} message - Alert message
 * @returns {Promise<string|null>} - Message ID or null
 */
export const sendSecurityAlert = async (token, message) => {
  return sendNotification(token, {
    title: 'Security Alert',
    body: message || 'Unusual activity detected on your account.',
    data: {
      type: 'security_alert',
      timestamp: new Date().toISOString(),
    },
  });
};
