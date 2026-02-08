import admin from 'firebase-admin';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { logger } from './logger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

let initialized = false;

export const initializeFirebase = async () => {
  try {
    if (initialized) {
      logger.info('Firebase already initialized');
      return admin;
    }

    // Load service account key from environment or file
    let serviceAccount;
    
    if (process.env.FIREBASE_SERVICE_ACCOUNT) {
      // If service account is provided as JSON string in env
      serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    } else {
      // Try to load from file
      const serviceAccountPath = join(__dirname, '../expensetracker-2759d-firebase-adminsdk-fbsvc-2e5908a05a.json');
      const fileContent = readFileSync(serviceAccountPath, 'utf8');
      serviceAccount = JSON.parse(fileContent);
    }

    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      projectId: process.env.FIREBASE_PROJECT_ID || 'expensetracker-2759d',
    });

    initialized = true;
    logger.info('✅ Firebase Admin SDK initialized successfully');
    return admin;
  } catch (error) {
    logger.warn('⚠️ Firebase Admin SDK not initialized (this is OK for testing):', error.message);
    logger.warn('📝 To enable FCM notifications, download service account from Firebase Console');
    logger.warn('   and save it as: expensetracker-2759d-firebase-adminsdk-fbsvc-2e5908a05a.json');
    // Don't throw - allow app to run without Firebase for testing
    initialized = false;
    return null;
  }
};

export const getMessaging = () => {
  if (!initialized) {
    logger.warn('Firebase not initialized - FCM notifications disabled');
    return null;
  }
  return admin.messaging();
};

export default admin;
