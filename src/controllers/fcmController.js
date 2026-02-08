import { updateUserFCMToken, getUserFCMToken, deleteFCMToken } from '../../utils/fcmTokenManager.js';
import { logger } from '../../config/logger.js';

/**
 * Store or update FCM token for authenticated user
 * POST /api/v1/auth/fcm/register-token
 */
export const registerFCMToken = async (req, res) => {
    try {
        const { token } = req.body;
        const userId = req.user?.id || req.decoded?.id;

        if (!userId) {
            return res.status(401).json({ message: 'User not authenticated' });
        }

        if (!token) {
            return res.status(400).json({ message: 'FCM token is required' });
        }

        const result = await updateUserFCMToken(userId, token);

        if (!result) {
            return res.status(404).json({ message: 'User not found' });
        }

        logger.info(`FCM token registered for user: ${userId}`);
        return res.status(200).json({
            message: 'FCM token registered successfully',
            data: result,
        });
    } catch (error) {
        logger.error('Error registering FCM token:', error);
        return res.status(500).json({
            message: 'Failed to register FCM token',
            error: error.message,
        });
    }
};

/**
 * Get FCM token for authenticated user
 * GET /api/v1/auth/fcm/token
 */
export const getFCMToken = async (req, res) => {
    try {
        const userId = req.user?.id || req.decoded?.id;

        if (!userId) {
            return res.status(401).json({ message: 'User not authenticated' });
        }

        const token = await getUserFCMToken(userId);
        

        return res.status(200).json({
            message: 'FCM token retrieved successfully',
            data: { token },
        });
    } catch (error) {
        logger.error('Error retrieving FCM token:', error);
        return res.status(500).json({
            message: 'Failed to retrieve FCM token',
            error: error.message,
        });
    }
};

/**
 * Delete FCM token for authenticated user
 * DELETE /api/v1/auth/fcm/token
 */
export const removeFCMToken = async (req, res) => {
    try {
        const userId = req.user?.id || req.decoded?.id;

        if (!userId) {
            return res.status(401).json({ message: 'User not authenticated' });
        }

        const result = await deleteFCMToken(userId);

        if (!result) {
            return res.status(404).json({ message: 'User not found' });
        }

        logger.info(`FCM token removed for user: ${userId}`);
        return res.status(200).json({
            message: 'FCM token removed successfully',
        });
    } catch (error) {
        logger.error('Error removing FCM token:', error);
        return res.status(500).json({
            message: 'Failed to remove FCM token',
            error: error.message,
        });
    }
};
