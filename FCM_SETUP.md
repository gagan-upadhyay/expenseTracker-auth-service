# Firebase Cloud Messaging (FCM) Setup Guide

## Overview
This guide explains the FCM integration with your auth service. When users log in, they receive a notification confirming their login status. The system stores their FCM tokens and sends them notifications on login/logout events.

## Setup Steps

### 1. Firebase Project Configuration
Your Firebase project is already configured. The service account key should be located at:
```
expensetracker-2759d-firebase-adminsdk-fbsvc-2e5908a05a.json
```

### 2. Database Migration
The system automatically adds the following columns to your `users` table on startup:
- `fcm_token` (TEXT) - Stores the user's FCM device token
- `fcm_token_updated_at` (TIMESTAMP) - Tracks when the token was last updated

### 3. Environment Variables
Add/update the following in your `.env` file:

```env
# Firebase Configuration
FIREBASE_PROJECT_ID=expensetracker-2759d
# FIREBASE_SERVICE_ACCOUNT=<optional-json-string>
```

If your service account file is in a different location, you can pass it as a JSON string:
```env
FIREBASE_SERVICE_ACCOUNT={"type":"service_account","project_id":"..."}
```

## API Endpoints

### Authentication Endpoints (Updated)

#### 1. **Login** - `/api/v1/auth/login`
```bash
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "message": "Logged In",
  "accessToken": "jwt_token",
  "refreshToken": "jwt_token"
}
```

**What happens:**
- User credentials are validated
- JWT tokens are generated and set as cookies
- **FCM notification is sent** to the user's device (if they have registered their token)
- Login notification: "Welcome back! You have successfully logged in."

---

#### 2. **Logout** - `/api/v1/auth/logout`
```bash
POST /api/v1/auth/logout
```

**Response:**
```json
{
  "message": "Successfully logged out"
}
```

**What happens:**
- User session is cleared
- **Logout notification is sent** to the user's device
- FCM token is removed from the database
- User is logged out from all sessions

---

### FCM Token Management Endpoints (New)

#### 3. **Register FCM Token** - `/api/v1/auth/fcm/register-token`
```bash
POST /api/v1/auth/fcm/register-token
Authorization: Bearer <accessToken>
Content-Type: application/json

{
  "token": "fcm_device_token_from_client"
}
```

**Response:**
```json
{
  "message": "FCM token registered successfully",
  "data": {
    "id": "user_id",
    "fcm_token": "device_token"
  }
}
```

**When to call:**
- After user logs in from a new device
- After FCM token is refreshed on the client side
- When requesting push notifications

---

#### 4. **Get FCM Token** - `/api/v1/auth/fcm/token`
```bash
GET /api/v1/auth/fcm/token
Authorization: Bearer <accessToken>
```

**Response:**
```json
{
  "message": "FCM token retrieved successfully",
  "data": {
    "token": "fcm_device_token_or_null"
  }
}
```

**Use case:**
- Verify if the user has registered their token
- For debugging purposes

---

#### 5. **Remove FCM Token** - `/api/v1/auth/fcm/token`
```bash
DELETE /api/v1/auth/fcm/token
Authorization: Bearer <accessToken>
```

**Response:**
```json
{
  "message": "FCM token removed successfully"
}
```

**When to call:**
- When user disables notifications
- When uninstalling the app
- When user logs out

---

## Frontend Integration

### Step 1: Set up FCM in your React/Next.js app

Install Firebase:
```bash
npm install firebase
```

Initialize Firebase (in your app):
```javascript
import { initializeApp } from 'firebase/app';
import { getMessaging, getToken } from 'firebase/messaging';

const firebaseConfig = {
  apiKey: "AIzaSyC2M1uA3Pp0zHsTCx6w14c_DX1sYfjodg0",
  authDomain: "expensetracker-2759d.firebaseapp.com",
  projectId: "expensetracker-2759d",
  storageBucket: "expensetracker-2759d.firebasestorage.app",
  messagingSenderId: "874326601085",
  appId: "1:874326601085:web:357c2be9efd52ea4bfb014",
  measurementId: "G-CLSK6WETHM"
};

const app = initializeApp(firebaseConfig);
const messaging = getMessaging(app);
```

### Step 2: Request notification permission and get token

```javascript
async function registerFCMToken(accessToken) {
  try {
    // Request notification permission
    const permission = await Notification.requestPermission();
    
    if (permission === 'granted') {
      // Get FCM token
      const token = await getToken(messaging, {
        vapidKey: 'YOUR_VAPID_KEY' // Get this from Firebase Console
      });
      
      if (token) {
        // Send token to backend
        const response = await fetch('/api/v1/auth/fcm/register-token', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${accessToken}`
          },
          body: JSON.stringify({ token })
        });
        
        const data = await response.json();
        console.log('FCM token registered:', data);
      }
    } else {
      console.log('Notification permission denied');
    }
  } catch (error) {
    console.error('Error registering FCM token:', error);
  }
}

// Call this after successful login
registerFCMToken(accessToken);
```

### Step 3: Handle incoming notifications

```javascript
import { onMessage } from 'firebase/messaging';

// Listen for messages when app is in foreground
onMessage(messaging, (payload) => {
  console.log('Message received:', payload);
  
  // Show custom notification
  const notification = {
    title: payload.notification.title,
    body: payload.notification.body,
    icon: '/icon.png'
  };
  
  // Handle notification (show toast, alert, etc.)
  showNotificationUI(notification);
});
```

### Step 4: Service Worker Setup

Create `public/firebase-messaging-sw.js`:
```javascript
importScripts('https://www.gstatic.com/firebasejs/10.0.0/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.0.0/firebase-messaging-compat.js');

firebase.initializeApp({
  apiKey: "AIzaSyC2M1uA3Pp0zHsTCx6w14c_DX1sYfjodg0",
  authDomain: "expensetracker-2759d.firebaseapp.com",
  projectId: "expensetracker-2759d",
  storageBucket: "expensetracker-2759d.firebasestorage.app",
  messagingSenderId: "874326601085",
  appId: "1:874326601085:web:357c2be9efd52ea4bfb014"
});

const messaging = firebase.messaging();

// Handle background messages
messaging.onBackgroundMessage((payload) => {
  console.log('Background message received:', payload);
  
  self.registration.showNotification(payload.notification.title, {
    body: payload.notification.body,
    icon: '/icon.png'
  });
});
```

---

## File Structure

New files created:
```
config/
  └── firebaseAdmin.js          # Firebase Admin SDK initialization
  
src/
  ├── controllers/
  │   └── fcmController.js       # FCM API endpoint handlers
  └── services/
      └── authService.js         # Updated with FCM notifications

utils/
  ├── fcmService.js              # FCM notification functions
  └── fcmTokenManager.js         # Database token management
```

Updated files:
```
src/
  ├── routes/AuthRoutes.js       # Added FCM token endpoints
  └── services/authService.js    # Integrated FCM in login/logout

index.js                         # Initialize Firebase on startup
.env                            # Added Firebase config variables
```

---

## Testing

### Test Login Notification
1. Open your app in browser
2. Request notification permission
3. Register FCM token via `/api/v1/auth/fcm/register-token`
4. Call `/api/v1/auth/login` with valid credentials
5. You should receive a "Login Successful" notification

### Test Logout Notification
1. Call `/api/v1/auth/logout`
2. You should receive a "Logged Out" notification
3. FCM token is automatically removed

### Debug FCM Issues
- Check browser console for Firebase errors
- Verify notification permission is granted
- Confirm FCM token is stored in database
- Check logs in Firebase Console

---

## Database Schema

The following columns are added to the `users` table:

```sql
ALTER TABLE users 
ADD COLUMN fcm_token TEXT,
ADD COLUMN fcm_token_updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
```

This is handled automatically by the `addFCMTokenColumn()` function on server startup.

---

## Error Handling

The system is designed to be fault-tolerant:
- If FCM notification fails, the login/logout still succeeds
- Errors are logged but don't interrupt the main flow
- Missing tokens are handled gracefully

---

## Security Considerations

1. **Token Security:**
   - Tokens are stored in the database
   - Only valid JWT tokens can register FCM tokens
   - Tokens are deleted on logout

2. **Authorization:**
   - All FCM endpoints require `verifySession` middleware
   - Only authenticated users can manage their tokens

3. **Data Privacy:**
   - FCM tokens are device-specific
   - Users can delete their tokens anytime

---

## Troubleshooting

### Issue: "Firebase not initialized"
**Solution:** Ensure the service account JSON file is in the correct path or set `FIREBASE_SERVICE_ACCOUNT` env variable.

### Issue: FCM token not being saved
**Solution:** 
1. Check if user is authenticated (has valid JWT)
2. Verify database connection
3. Check logs for SQL errors

### Issue: Notifications not received on the client
**Solution:**
1. Verify notification permission is granted in browser
2. Check FCM token is registered
3. Ensure service worker is properly loaded
4. Check Firebase project configuration in web app

### Issue: Database migration fails
**Solution:**
1. Ensure PostgreSQL user has ALTER TABLE permissions
2. Check if columns already exist
3. Review server logs for specific SQL errors

---

## Next Steps

1. Get VAPID key from Firebase Console (Project Settings → Cloud Messaging)
2. Integrate FCM token registration in your frontend after login
3. Test notifications in development
4. Deploy to production

For more info: https://firebase.google.com/docs/cloud-messaging
