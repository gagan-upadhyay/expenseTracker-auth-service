# 🎉 FCM Testing - START HERE

## ✅ Your Server is Running

**URL:** `http://localhost:5000`

**Check logs in your terminal:**
```
✅ Redis connected
✅ Database schema updated for FCM support
⚠️ Firebase Admin SDK not initialized (this is OK for testing)
```

---

## 📋 Quick Test Checklist

Open **Postman** or **Insomnia** and test these 7 requests in order:

### 1️⃣ Register User
```
POST http://localhost:5000/api/v1/auth/register
Content-Type: application/json

{
  "username": "testuser",
  "email": "test@example.com",
  "password": "TestPassword@123"
}
```
✅ **Expected:** `201 Created`

---

### 2️⃣ Login
```
POST http://localhost:5000/api/v1/auth/login
Content-Type: application/json

{
  "email": "test@example.com",
  "password": "TestPassword@123"
}
```
✅ **Expected:** `200 OK` + cookies set

---

### 3️⃣ Register FCM Token
```
POST http://localhost:5000/api/v1/auth/fcm/register-token
Content-Type: application/json
Cookie: accessToken=<token_from_login>

{
  "fcmToken": "test-device-token-12345"
}
```
✅ **Expected:** `200 OK`

---

### 4️⃣ Get Your Token
```
GET http://localhost:5000/api/v1/auth/fcm/token
Cookie: accessToken=<token_from_login>
```
✅ **Expected:** `200 OK` with your token

---

### 5️⃣ Login Again (Triggers FCM)
```
POST http://localhost:5000/api/v1/auth/login
Content-Type: application/json

{
  "email": "test@example.com",
  "password": "TestPassword@123"
}
```
✅ **Expected:** `200 OK` + check server logs

**Watch server logs** - should show:
```
FCM not initialized - skipping notification
```
(This is normal - will send real notifications once Firebase credentials added)

---

### 6️⃣ Logout (Cleanup)
```
POST http://localhost:5000/api/v1/auth/logout
Cookie: accessToken=<token_from_login>
```
✅ **Expected:** `200 OK` + token deleted from database

---

### 7️⃣ Verify Token Deleted
```
GET http://localhost:5000/api/v1/auth/fcm/token
Cookie: accessToken=<token_from_login>
```
✅ **Expected:** `404 Not Found`

---

## 📚 Documentation Files

| File | What to Read |
|------|--------------|
| `POSTMAN_TESTING.md` | 📋 Detailed test requests with expected responses |
| `TESTING_GUIDE.md` | 📖 Comprehensive setup + troubleshooting |
| `TESTING_STATUS.md` | 📊 Current system status + architecture |
| `FCM_QUICK_START.md` | ⚡ 5-minute Firebase setup guide |
| `FCM_SETUP.md` | 🔧 Full technical documentation |
| `FRONTEND_FCM_INTEGRATION.js` | 🎨 React/Vue implementation example |
| `DEPLOYMENT_CHECKLIST.md` | ✅ Before going to production |

---

## 🔥 Next Steps

### Right Now
1. Open **POSTMAN_TESTING.md**
2. Test all 7 endpoints in order
3. All should pass ✅

### When Ready for Firebase
1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Project: **expensetracker-2759d**
3. ⚙️ Settings → Service Accounts
4. **Generate New Private Key**
5. Save as: `expensetracker-2759d-firebase-adminsdk-fbsvc-2e5908a05a.json`
6. Restart server: `npm run dev`
7. Logs will show: `✅ Firebase Admin SDK initialized successfully`

### For Frontend Integration
1. Read `FRONTEND_FCM_INTEGRATION.js`
2. Add Firebase to your React/Vue app
3. Request notification permission
4. Get real device token
5. Send to `/api/v1/auth/fcm/register-token`
6. Login and see notifications! 🎉

---

## 🚨 If Tests Fail

| Error | Solution |
|-------|----------|
| **Can't connect to localhost:5000** | Make sure `npm run dev` is running in npm terminal |
| **"FCM token is missing"** | This is normal - register one first (step 3) |
| **"FCM not initialized"** | This is OK - Firebase not required for auth testing |
| **Cookie not set on login** | Check CORS - origin might be blocked |
| **Database error** | Database auto-migrates on startup. Check PostgreSQL is accessible |

---

## 📊 Architecture Overview

```
Your Frontend (React/Vue)
        ↓
    HTTP Request
        ↓
Express Server (Port 5000)
├── Auth Endpoints (/api/v1/auth/login, /register, /logout)
├── FCM Token Management (/api/v1/auth/fcm/*)
├── JWT Verification (Cookies)
└── Database Queries
        ↓
PostgreSQL Database
├── users table (with fcm_token column)
├── Sessions (stored in Redis)
└── Tokens
```

---

## ✨ What Happens Behind the Scenes

1. **User registers** → Hashed password stored, JWT created
2. **User logs in** → Token stored in DB + Redis, cookie set
3. **User registers FCM token** → Token stored in `users.fcm_token`
4. **User logs in again** → Notification sent (when Firebase ready)
5. **User logs out** → Token deleted, session cleared
6. **Token expires** → Refresh token can get new access token

---

## 💡 Pro Tips

✅ **Use cookie-based auth** - Postman automatically handles cookies between requests

✅ **Copy-paste requests** - All requests in POSTMAN_TESTING.md are ready to use

✅ **Check server logs** - Most information is in the npm terminal, not response bodies

✅ **Test with real data** - Use unique emails so you can test multiple users

✅ **Database auto-migrates** - No manual SQL needed, happens on startup

---

## 🎯 Success Criteria

You're done when:
- [ ] All 7 Postman tests pass
- [ ] No error-level logs (warnings OK)
- [ ] Can login/logout multiple times
- [ ] FCM token management works
- [ ] Database has fcm_token column

**Then you're ready for:**
- Frontend integration
- Production deployment
- Real Firebase notifications

---

## 📞 Quick Reference

**Server:** `npm run dev` (in project root)

**Test:** Use POSTMAN_TESTING.md requests

**Logs:** Check npm terminal for all activity

**Database:** PostgreSQL at endpoint in .env

**Cache:** Redis for sessions/tokens

---

**🚀 Ready? Open POSTMAN_TESTING.md and start testing!**
