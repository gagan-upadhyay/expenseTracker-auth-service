# FCM Quick Start Guide

## What's Been Set Up

Your auth service now has **complete FCM integration** for sending notifications when users log in or out.

## Files Created/Modified

### New Files:
- `config/firebaseAdmin.js` - Firebase Admin SDK initialization
- `utils/fcmService.js` - Notification sending functions
- `utils/fcmTokenManager.js` - Database token management  
- `src/controllers/fcmController.js` - API endpoint handlers
- `FCM_SETUP.md` - Comprehensive documentation

### Modified Files:
- `src/services/authService.js` - Added FCM calls in login/logout
- `src/routes/AuthRoutes.js` - Added FCM token endpoints
- `index.js` - Initialize Firebase on startup
- `.env` - Added Firebase config

## Quick Setup Checklist

### 1. Verify Firebase Service Account
Your service account file should exist at:
```
expensetracker-2759d-firebase-adminsdk-fbsvc-2e5908a05a.json
```

If not in the root, update the path in `config/firebaseAdmin.js` or set the env variable.

### 2. Start Your Server
```powershell
npm run dev
# or
node index.js
```

You'll see:
```
Firebase Admin SDK initialized
Database schema updated for FCM support
```

### 3. Test the Flow

**Option A: Using Postman/cURL**

```bash
# 1. Register FCM token (requires valid accessToken)
POST /api/v1/auth/fcm/register-token
Header: Authorization: Bearer <your_access_token>
Body: { "token": "sample_fcm_token_here" }

# 2. Login (notification sent if token exists)
POST /api/v1/auth/login
Body: { "email": "user@example.com", "password": "pass" }

# 3. Logout (notification sent, token deleted)
POST /api/v1/auth/logout
```

**Option B: In Your Frontend App**

```javascript
// 1. After successful login, register FCM token
const token = await getToken(messaging, { vapidKey: 'YOUR_KEY' });
await fetch('/api/v1/auth/fcm/register-token', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ token })
});

// 2. Notification will be sent automatically on login
// 3. Notification will be sent automatically on logout
```

## API Endpoints

| Method | Endpoint | Purpose | Auth |
|--------|----------|---------|------|
| POST | `/api/v1/auth/login` | Login + send notification | No |
| POST | `/api/v1/auth/logout` | Logout + send notification | Yes |
| POST | `/api/v1/auth/fcm/register-token` | Register device token | Yes |
| GET | `/api/v1/auth/fcm/token` | Get user's FCM token | Yes |
| DELETE | `/api/v1/auth/fcm/token` | Delete user's FCM token | Yes |

## How It Works

### Login Flow:
1. User logs in with email/password
2. JWT tokens are generated
3. **Check if FCM token exists in database**
4. **Send "Login Successful" notification** to device
5. Return tokens to client

### Logout Flow:
1. User logs out (sends valid access token)
2. **Check if FCM token exists**
3. **Send "Logged Out" notification**
4. **Delete FCM token from database**
5. Clear session and return success

### Token Registration:
1. Client requests notification permission
2. Client gets FCM token from Firebase
3. Client sends token to backend
4. **Backend saves token in database**
5. Notifications are sent using this token

## Database Changes

The system automatically adds these columns on startup:

```sql
ALTER TABLE users 
ADD COLUMN fcm_token TEXT;
ADD COLUMN fcm_token_updated_at TIMESTAMP;
```

No manual migration needed!

## Environment Variables

Add to `.env`:
```env
FIREBASE_PROJECT_ID=expensetracker-2759d
```

Optional (if service account is elsewhere):
```env
FIREBASE_SERVICE_ACCOUNT={"type":"service_account",...}
```

## Logging

All FCM operations are logged. Check logs for:
- "Firebase Admin SDK initialized"
- "FCM notification sent successfully"
- "FCM token registered for user"
- "FCM token deleted for user"

## Troubleshooting

**Q: No notifications showing?**
A: Check if:
1. Service account file exists
2. FCM token is registered in database
3. Frontend has notification permission
4. Service Worker is running

**Q: "Firebase not initialized" error?**
A: Ensure service account JSON file path is correct in `config/firebaseAdmin.js`

**Q: Database column already exists error?**
A: The migration checks if columns exist - this is safe to run multiple times

## Next Steps

1. ✅ FCM is set up and ready
2.📱 Integrate frontend notification handling (see `FCM_SETUP.md`)
3. 🧪 Test login/logout notifications
4. 🚀 Deploy to production

## Support

See `FCM_SETUP.md` for:
- Detailed frontend integration
- VAPID key setup
- Service worker configuration
- Error handling
- Testing procedures
