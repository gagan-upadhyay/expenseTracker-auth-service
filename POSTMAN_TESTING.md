# FCM Integration Testing - Postman Collection

## Quick Test Summary

Your server is **running on http://localhost:5000** with:
- ✅ Redis connected
- ✅ PostgreSQL ready
- ✅ Authentication system active
- ✅ Database schema migrated for FCM support
- ⚠️ Firebase (optional) - not critical for auth testing

---

## Testing Steps (Copy-paste these into Postman)

### **1. Register a New Test User**

**Method:** POST  
**URL:** `http://localhost:5000/api/v1/auth/register`  
**Headers:**
```
Content-Type: application/json
```

**Body (raw JSON):**
```json
{
  "username": "testuser123",
  "email": "testuser123@example.com",
  "password": "TestPassword@123"
}
```

**Expected Response:** `201 Created`
```json
{
  "success": true,
  "message": "User registered successfully",
  "user": {
    "id": "...",
    "username": "testuser123",
    "email": "testuser123@example.com"
  }
}
```

**Save these from response cookies for next steps:**
- `accessToken` (in Set-Cookie header)
- `refreshToken` (in Set-Cookie header)

---

### **2. Login & Trigger Auth Flow**

**Method:** POST  
**URL:** `http://localhost:5000/api/v1/auth/login`  
**Headers:**
```
Content-Type: application/json
```

**Body (raw JSON):**
```json
{
  "email": "testuser123@example.com",
  "password": "TestPassword@123"
}
```

**Expected Response:** `200 OK`
```json
{
  "success": true,
  "message": "Login successful",
  "user": {
    "id": "...",
    "email": "testuser123@example.com"
  }
}
```

**⚠️ Note:** FCM notification skipped here because no token registered yet.

---

### **3. Register an FCM Device Token**

**Method:** POST  
**URL:** `http://localhost:5000/api/v1/auth/fcm/register-token`  
**Headers:**
```
Content-Type: application/json
Cookie: accessToken=<your_access_token_from_login>
```

**Body (raw JSON):**
```json
{
  "fcmToken": "test-device-token-12345"
}
```

**Expected Response:** `200 OK`
```json
{
  "success": true,
  "message": "FCM token registered successfully"
}
```

**What happened in database:**
- Your `fcm_token` column now has: `"test-device-token-12345"`
- Your `fcm_token_updated_at` shows current timestamp

---

### **4. Get Your Registered Token**

**Method:** GET  
**URL:** `http://localhost:5000/api/v1/auth/fcm/token`  
**Headers:**
```
Cookie: accessToken=<your_access_token>
```

**Expected Response:** `200 OK`
```json
{
  "success": true,
  "fcmToken": "test-device-token-12345"
}
```

---

### **5. Login Again (Now FCM Notification Triggers)**

**Method:** POST  
**URL:** `http://localhost:5000/api/v1/auth/login`  
**Headers:**
```
Content-Type: application/json
```

**Body (raw JSON):**
```json
{
  "email": "testuser123@example.com",
  "password": "TestPassword@123"
}
```

**Expected Response:** `200 OK`

**Check Server Logs (npm terminal):**
- You should see: `"FCM not initialized - skipping notification"` (because Firebase creds not ready)
- This is **normal** - when real Firebase credentials are added, this will send actual notifications

---

### **6. Logout & Trigger Token Cleanup**

**Method:** POST  
**URL:** `http://localhost:5000/api/v1/auth/logout`  
**Headers:**
```
Cookie: accessToken=<your_access_token>
```

**Expected Response:** `200 OK`
```json
{
  "success": true,
  "message": "Logout successful"
}
```

**What happened:**
- Server logs: "FCM token deleted"
- Database: Your `fcm_token` is now `NULL`

---

### **7. Verify Token Was Deleted**

**Method:** GET  
**URL:** `http://localhost:5000/api/v1/auth/fcm/token`  
**Headers:**
```
Cookie: accessToken=<your_access_token>
```

**Expected Response:** `404 Not Found`
```json
{
  "success": false,
  "message": "No FCM token found for this user"
}
```

---

### **8. Delete Token Manually (Optional)**

**Method:** DELETE  
**URL:** `http://localhost:5000/api/v1/auth/fcm/token`  
**Headers:**
```
Cookie: accessToken=<your_access_token>
```

**Expected Response:** `200 OK`
```json
{
  "success": true,
  "message": "FCM token deleted successfully"
}
```

---

## Troubleshooting Test Issues

### "FCM token is missing" in logs
✅ **This is normal** - means you haven't registered a token yet. Go to Step 3.

### "FCM not initialized" in logs
✅ **This is normal** - Firebase credentials not added yet. This message changes to notification sent once you:
1. Get real service account from Firebase Console
2. Save file with correct name
3. Restart server

### Login doesn't set cookies
❌ **Problem:** Check if CORS is blocking requests
- Solution: Make sure your Postman origin matches CORS config (localhost:3000 or your IP)

### Database errors
❌ **Problem:** "fcm_token column not found"
- Solution: Server auto-creates it on startup. Restart with `npm run dev`

---

## Next: Get Real Firebase Credentials

Once testing shows everything works, follow these steps:

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Select your project: **expensetracker-2759d**
3. **⚙️ Project Settings** → **Service Accounts** tab
4. Click **Generate New Private Key**
5. A JSON file downloads - save it in project root as:
   ```
   expensetracker-2759d-firebase-adminsdk-fbsvc-2e5908a05a.json
   ```
6. Restart server: `npm run dev`
7. Logs will show: `"✅ Firebase Admin SDK initialized successfully"`
8. Then notifications will actually send!

---
    
## Final Checklist

- [ ] Server starts without errors
- [ ] Register user successfully
- [ ] Login works
- [ ] Register FCM token works
- [ ] Get token returns your token
- [ ] Logout deletes token
- [ ] All endpoints respond with correct status codes
- [ ] No "error" level logs (warnings are OK)

**✅ If all checkmarks pass, backend is production-ready for frontend integration!**
