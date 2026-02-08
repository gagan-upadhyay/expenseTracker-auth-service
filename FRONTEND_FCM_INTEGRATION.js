/**
 * Firebase FCM Integration Example
 * Use this as a reference for your React/Next.js frontend
 */

// ==========================================
// 1. Firebase Configuration & Initialization
// ==========================================

import { initializeApp } from 'firebase/app';
import { getMessaging, getToken, onMessage } from 'firebase/messaging';

const firebaseConfig = {
  apiKey: "AIzaSyC2M1uA3Pp0zHsTCx6w14c_DX1sYfjodg0",
  authDomain: "expensetracker-2759d.firebaseapp.com",
  projectId: "expensetracker-2759d",
  storageBucket: "expensetracker-2759d.firebasestorage.app",
  messagingSenderId: "874326601085",
  appId: "1:874326601085:web:357c2be9efd52ea4bfb014",
  measurementId: "G-CLSK6WETHM"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const messaging = getMessaging(app);

// Export for use in other modules
export { messaging };

// ==========================================
// 2. Request Notification Permission
// ==========================================

export async function requestNotificationPermission() {
  try {
    // Check if browser supports notifications
    if (!('Notification' in window)) {
      console.log('This browser does not support notifications');
      return null;
    }

    // Check if already granted
    if (Notification.permission === 'granted') {
      console.log('Notification permission already granted');
      return true;
    }

    // Request permission if not denied
    if (Notification.permission !== 'denied') {
      const permission = await Notification.requestPermission();
      return permission === 'granted';
    }

    return false;
  } catch (error) {
    console.error('Error requesting notification permission:', error);
    return false;
  }
}

// ==========================================
// 3. Register FCM Token with Backend
// ==========================================

export async function registerFCMToken(accessToken) {
  try {
    // Check notification permission first
    const hasPermission = await requestNotificationPermission();
    if (!hasPermission) {
      console.log('User denied notification permission');
      return null;
    }

    // Get FCM token
    // Note: Replace with your VAPID key from Firebase Console
    const VAPID_KEY = process.env.REACT_APP_FIREBASE_VAPID_KEY || 'YOUR_VAPID_KEY';
    
    const token = await getToken(messaging, {
      vapidKey: VAPID_KEY
    });

    if (!token) {
      console.log('No FCM token available');
      return null;
    }

    console.log('FCM Token:', token);

    // Send token to backend
    const response = await fetch('/api/v1/auth/fcm/register-token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
      },
      credentials: 'include',
      body: JSON.stringify({ token })
    });

    if (!response.ok) {
      throw new Error(`Failed to register FCM token: ${response.statusText}`);
    }

    const data = await response.json();
    console.log('FCM token registered successfully:', data);
    return token;
  } catch (error) {
    console.error('Error registering FCM token:', error);
    return null;
  }
}

// ==========================================
// 4. Handle Foreground Messages
// ==========================================

export function setupForegroundMessageListener() {
  onMessage(messaging, (payload) => {
    console.log('Message received in foreground:', payload);

    // Extract notification data
    const { notification, data } = payload;

    // Show custom notification UI (you can use a toast library here)
    showNotificationToast({
      title: notification?.title || 'Notification',
      body: notification?.body || '',
      type: data?.type || 'info'
    });

    // Handle specific notification types
    if (data?.type === 'login') {
      console.log('User logged in from another device');
    } else if (data?.type === 'logout') {
      console.log('User logged out');
    } else if (data?.type === 'security_alert') {
      console.log('Security alert:', notification?.body);
    }
  });
}

// ==========================================
// 5. Login Handler (Call after backend login)
// ==========================================

export async function handleLoginWithFCM(email, password) {
  try {
    // 1. Call backend login endpoint
    const loginResponse = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'include',
      body: JSON.stringify({ email, password })
    });

    if (!loginResponse.ok) {
      throw new Error('Login failed');
    }

    const { accessToken } = await loginResponse.json();

    // 2. Register FCM token (triggers notification from backend)
    // Do this asynchronously - don't wait for it
    registerFCMToken(accessToken).catch(error => {
      console.error('Failed to register FCM token:', error);
      // Continue anyway - login is still successful
    });

    return { success: true, accessToken };
  } catch (error) {
    console.error('Login error:', error);
    return { success: false, error: error.message };
  }
}

// ==========================================
// 6. Logout Handler
// ==========================================

export async function handleLogoutWithFCM() {
  try {
    // Call backend logout (triggers notification and token deletion)
    const response = await fetch('/api/v1/auth/logout', {
      method: 'POST',
      credentials: 'include'
    });

    if (!response.ok) {
      throw new Error('Logout failed');
    }

    console.log('Successfully logged out');
    return { success: true };
  } catch (error) {
    console.error('Logout error:', error);
    return { success: false, error: error.message };
  }
}

// ==========================================
// 7. Utility: Show Notification Toast
// ==========================================

function showNotificationToast({ title, body, type = 'info' }) {
  // Example using a simple toast (replace with your toast library)
  console.log(`[${type.toUpperCase()}] ${title}: ${body}`);

  // If using react-hot-toast:
  // toast.success(`${title}: ${body}`);

  // If using react-toastify:
  // toast[type](`${title}: ${body}`);

  // If using custom implementation:
  // showCustomToast({ title, body, type });
}

// ==========================================
// 8. Initialize on App Load
// ==========================================

export function initializeFirebaseMessaging() {
  try {
    // Request notification permission
    requestNotificationPermission();

    // Setup foreground message listener
    setupForegroundMessageListener();

    console.log('Firebase messaging initialized');
  } catch (error) {
    console.error('Error initializing Firebase messaging:', error);
  }
}

// ==========================================
// 9. React Hook Example (Use in your component)
// ==========================================

// import { useEffect, useState } from 'react';

// export function useFirebaseMessaging() {
//   const [token, setToken] = useState(null);
//   const [notification, setNotification] = useState(null);

//   useEffect(() => {
//     // Initialize on component mount
//     initializeFirebaseMessaging();

//     // Setup message listener
//     const unsubscribe = onMessage(messaging, (payload) => {
//       setNotification({
//         title: payload.notification?.title,
//         body: payload.notification?.body,
//         type: payload.data?.type
//       });
//     });

//     return unsubscribe;
//   }, []);

//   return { token, notification };
// }

// ==========================================
// 10. Usage Example in Your App
// ==========================================

/*
// In your login component:
import { handleLoginWithFCM, initializeFirebaseMessaging } from './firebaseMessaging';

export function LoginComponent() {
  useEffect(() => {
    // Initialize on app load
    initializeFirebaseMessaging();
  }, []);

  const handleLogin = async (email, password) => {
    const result = await handleLoginWithFCM(email, password);
    if (result.success) {
      // Redirect to dashboard
    } else {
      // Show error
    }
  };

  return (
    <form onSubmit={(e) => {
      e.preventDefault();
      handleLogin(email, password);
    }}>
      {/* form fields */
//     </form>
//   );
// }

// In your logout button:
// import { handleLogoutWithFCM } from './firebaseMessaging';

// export function LogoutButton() {
//   const handleLogout = async () => {
//     await handleLogoutWithFCM();
//     // Redirect to login
//   };

//   return <button onClick={handleLogout}>Logout</button>;
// }


// ==========================================
// 11. Environment Variables (.env.local)
// ==========================================

/*
REACT_APP_FIREBASE_API_KEY=AIzaSyC2M1uA3Pp0zHsTCx6w14c_DX1sYfjodg0
REACT_APP_FIREBASE_AUTH_DOMAIN=expensetracker-2759d.firebaseapp.com
REACT_APP_FIREBASE_PROJECT_ID=expensetracker-2759d
REACT_APP_FIREBASE_STORAGE_BUCKET=expensetracker-2759d.firebasestorage.app
REACT_APP_FIREBASE_MESSAGING_SENDER_ID=874326601085
REACT_APP_FIREBASE_APP_ID=1:874326601085:web:357c2be9efd52ea4bfb014
REACT_APP_FIREBASE_MEASUREMENT_ID=G-CLSK6WETHM
REACT_APP_FIREBASE_VAPID_KEY=your_vapid_key_here
*/
