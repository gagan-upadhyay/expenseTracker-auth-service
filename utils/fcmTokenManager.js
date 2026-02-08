import { pgQuery } from '../config/dbconnection.js';
import { logger } from '../config/logger.js';

/**
 * Add FCM token column to users table if it doesn't exist
 */
// export const addFCMTokenColumn = async () => {
//   try {
//     // Check if column exists
//     const checkColumnQuery = `
//       SELECT EXISTS (
//         SELECT FROM information_schema.columns 
//         WHERE table_name = 'users' AND column_name = 'fcm_token'
//       );
//     `;
    
//     const result = await pgQuery(checkColumnQuery, []);
    
//     if (!result.rows[0].exists) {
//       const addColumnQuery = `
//         ALTER TABLE users 
//         ADD COLUMN fcm_token TEXT,
//         ADD COLUMN fcm_token_updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
//       `;
      
//       await pgQuery(addColumnQuery, []);
//       logger.info('Successfully added fcm_token and fcm_token_updated_at columns to users table');
//     } else {
//       logger.info('fcm_token column already exists in users table');
//     }
//   } catch (error) {
//     logger.error('Error adding FCM token column:', error);
//     throw error;
//   }
// };

/**
 * Update FCM token for a user
 */
export const updateUserFCMToken = async (userId, fcmToken) => {
  try {
    const query = `
      UPDATE users 
      SET fcm_token = $1, fcm_token_updated_at = CURRENT_TIMESTAMP
      WHERE id = $2
      RETURNING id, fcm_token;
    `;
    
    const result = await pgQuery(query, [fcmToken, userId]);
    
    if (result.rows.length === 0) {
      logger.warn(`User not found for ID: ${userId}`);
      return null;
    }
    
    logger.info(`FCM token updated for user: ${userId}`);
    return result.rows[0];
  } catch (error) {
    logger.error('Error updating FCM token:', error);
    throw error;
  }
};

/**
 * Get FCM token for a user
 */
export const getUserFCMToken = async (userId) => {
  try {
    const query = `SELECT fcm_token FROM users WHERE id = $1;`;
    const result = await pgQuery(query, [userId]);
    console.log('Value of result.rows[0].fcm_token from fcmTokenManager:\n', result.rows[0].fcm_token);
    
    if (result.rows.length === 0) {
      return null;
    }
    
    return result.rows[0].fcm_token;
  } catch (error) {
    logger.error('Error retrieving FCM token:', error);
    throw error;
  }
};

/**
 * Get all active FCM tokens (for multicast notifications)
 */
export const getAllActiveFCMTokens = async () => {
  try {
    const query = `
      SELECT id, fcm_token FROM users 
      WHERE fcm_token IS NOT NULL 
      AND fcm_token != ''
      ORDER BY fcm_token_updated_at DESC;
    `;
    
    const result = await pgQuery(query, []);
    return result.rows.map(row => row.fcm_token);
  } catch (error) {
    logger.error('Error retrieving active FCM tokens:', error);
    throw error;
  }
};

/**
 * Delete FCM token for a user (on logout)
 */
export const deleteFCMToken = async (userId) => {
  try {
    const query = `
      UPDATE users 
      SET fcm_token = NULL, fcm_token_updated_at = CURRENT_TIMESTAMP
      WHERE id = $1
      RETURNING id;
    `;
    
    const result = await pgQuery(query, [userId]);
    
    if (result.rows.length === 0) {
      logger.warn(`User not found for ID: ${userId}`);
      return null;
    }
    
    logger.info(`FCM token deleted for user: ${userId}`);
    return result.rows[0];
  } catch (error) {
    logger.error('Error deleting FCM token:', error);
    throw error;
  }
};
