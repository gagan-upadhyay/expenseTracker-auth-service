# FCM Integration Testing Guide

## Phase 1: Get Firebase Service Account Credentials

### Step 1: Download Service Account Key from Firebase Console

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Select your project: **expensetracker-2759d**
3. Click **⚙️ Project Settings** (gear icon, top left)
4. Go to **Service Accounts** tab
5. Click **Generate New Private Key** button
6. A JSON file will download
7. **Save it in your project root** with this exact filename:
   ```
   expensetracker-2759d-firebase-adminsdk-fbsvc-2e5908a05a.json
   ```

### Step 2: Verify File Location
After saving, your project structure should look like:
```
expenseTracker-auth-service/
├── index.js
├── package.json
├── expensetracker-2759d-firebase-adminsdk-fbsvc-2e5908a05a.json  ← HERE
├── config/
├── src/
└── ...
```

---

## Phase 2: Test Backend Initialization

### Step 1: Start the Server
```powershell
npm run dev
```

### Step 2: Look for These Success Logs
Check your terminal output for:
```
Firebase Admin SDK initialized
Database schema updated for FCM support
listening on port 5000
```

### Step 3: If You See Errors
If Firebase fails to initialize, check:
- ❌ Is the service account file in the correct location?
- ❌ Is the filename exactly correct? (case-sensitive on Linux/Mac)
- ❌ Does the file have valid JSON? (open it and check)
- ❌ Is `.env` pointing to the right project ID?

---

## Phase 3: Test API Endpoints with Postman

### Test 1: Register a New User (Create Account)
```
POST /api/v1/auth/register
Content-Type: application/json

{
  "username": "testuser",
  "email": "test@example.com",
  "password": "TestPassword123!"
}
```
**Expected:** 201 Created

---

### Test 2: Login & Trigger FCM Notification (WITHOUT FCM Token)
```
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "test@example.com",
  "password": "TestPassword123!"
}
```
**Expected Response:**
- Status: 200 OK
- Cookies: `accessToken` + `refreshToken`
- In logs: "FCM token not provided" (because no token registered yet)

---

### Test 3: Register FCM Token (Prepare for Notifications)
```
POST /api/v1/auth/fcm/register-token
Content-Type: application/json
Cookie: accessToken=<your-access-token-from-login>

{
  "fcmToken": "test-fcm-device-token-12345"
}
```
**Expected:** 200 OK
**In Database:** User's fcm_token column now has `test-fcm-device-token-12345`

---

### Test 4: Login Again & Trigger Real Notification
```
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "test@example.com",
  "password": "TestPassword123!"
}
```
**Expected:**
- Status: 200 OK
- **Server Logs:** Should show FCM notification sent
- **Console Logs:** 
  ```
  Sending login notification to token: test-fcm-device-token-12345
  Login notification sent successfully
  ```

---

### Test 5: Retrieve Registered Token
```
GET /api/v1/auth/fcm/token
Cookie: accessToken=<your-access-token>
```
**Expected Response:**
```json
{
  "success": true,
  "fcmToken": "test-fcm-device-token-12345"
}
```

---

### Test 6: Logout & Test Notification Cleanup
```
POST /api/v1/auth/logout
Cookie: accessToken=<your-access-token>
```
**Expected:**
- Status: 200 OK
- Server Logs: "Logout notification sent" + "FCM token deleted"
- **In Database:** User's fcm_token column set back to NULL

---

### Test 7: Delete FCM Token Manually
```
DELETE /api/v1/auth/fcm/token
Cookie: accessToken=<your-access-token>
```
**Expected:** 200 OK with message "FCM token deleted"

---

## Phase 4: Test with Real Firebase Device Token (Mobile App)

Once your backend is working, follow `FRONTEND_FCM_INTEGRATION.js` to:
1. Add Firebase to your React app
2. Request notification permission from user
3. Get real device token via:
   ```javascript
   const token = await messaging.getToken();
   ```
4. Send token to `/api/v1/auth/fcm/register-token`
5. Login and watch notifications appear on device!

---

## Phase 5: Verify Database Changes

### Check if fcm_token column exists:
```sql
SELECT * FROM users LIMIT 1;
-- Should show new column: fcm_token (text, nullable)
-- Should show new column: fcm_token_updated_at (timestamp)
```

### View actual tokens stored:
```sql
SELECT id, email, fcm_token, fcm_token_updated_at FROM users;
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| **"Firebase not initialized"** | Service account file missing. Download from Firebase Console. |
| **"Invalid JSON in service account"** | Open the file and check for corruption. Redownload from Firebase. |
| **"FCM token not provided"** | This is normal - it means you haven't registered a token yet. Test continues. |
| **"PERMISSION_DENIED sending message"** | Service account doesn't have messaging permissions. Regenerate key. |
| **Database migration failed** | PostgreSQL user needs ALTER TABLE permissions. Check DB user role. |
| **Notifications not showing on device** | Tokens must be real (from `getToken()`), not test strings. Use frontend integration. |

---

## Quick Checklist

- [ ] Downloaded service account file from Firebase Console
- [ ] Saved file in project root with correct filename
- [ ] Started server with `npm run dev`
- [ ] Saw "Firebase Admin SDK initialized" in logs
- [ ] Tested register endpoint
- [ ] Tested login endpoint
- [ ] Tested FCM token registration
- [ ] Tested FCM token retrieval
- [ ] Tested logout (token cleanup)
- [ ] Integrated with frontend app (optional but recommended)

---

## Next Steps After Testing

1. **Frontend Integration** - Follow `FRONTEND_FCM_INTEGRATION.js`
2. **Production Deployment** - Follow `DEPLOYMENT_CHECKLIST.md`
3. **Monitor Notifications** - Use Firebase Console → Logs
4. **Set Up Error Handling** - Read `FCM_INTEGRATION_COMPLETE.md`
