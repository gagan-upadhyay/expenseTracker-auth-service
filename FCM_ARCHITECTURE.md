# FCM Integration - Architecture & Flow Diagrams

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    EXPENSE TRACKER APP                       │
│  ┌──────────────────────────────────────────────────────┐  │
│  │         Frontend (React/Next.js)                     │  │
│  │  - Firebase SDK                                      │  │
│  │  - Request Notification Permission                  │  │
│  │  - Register FCM Token                               │  │
│  │  - Listen for Messages                              │  │
│  └────────────────┬─────────────────────────────────────┘  │
│                   │ HTTPS                                    │
└───────────────────┼────────────────────────────────────────┘
                    │
                    ▼
         ┌──────────────────────────┐
         │   Express Backend        │
         │  (Auth Service)          │
         │                          │
         │  /api/v1/auth/login ◄────┤─ User Login Request
         │  /api/v1/auth/logout     │
         │  /api/v1/auth/fcm/*      │
         └────────┬──────────────────┘
                  │
        ┌─────────┼─────────┐
        │         │         │
        ▼         ▼         ▼
    ┌────┐   ┌────────┐  ┌──────────────────┐
    │ DB │   │ Redis  │  │ Firebase Cloud   │
    │    │   │        │  │ Messaging (FCM)  │
    │fcm_│   │ Tokens │  │                  │
    │token    │        │  │ - Send Notif.   │
    └────┘   └────────┘  │ - Queue Msgs     │
                         │ - Track Delivery │
                         └──────────┬───────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ Firebase Cloud      │
                         │ Messaging (Backend) │
                         └─────────────────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   User Devices      │
                         │ (Phone/Browser)     │
                         │ - Notification      │
                         └─────────────────────┘
```

---

## Login Flow with FCM

```
┌─────────────────────────────────────────────────────────────────┐
│                        LOGIN FLOW                               │
└─────────────────────────────────────────────────────────────────┘

User Browser                  Auth Service              Firebase
     │                              │                        │
     │ 1. POST /login               │                        │
     │─────────────────────────────>│                        │
     │   (email, password)          │                        │
     │                              │                        │
     │                    2. Validate Credentials            │
     │                       (bcrypt compare)                │
     │                              │                        │
     │                    3. Generate JWT Tokens            │
     │                       (access + refresh)             │
     │                              │                        │
     │                    4. Get FCM Token from DB           │
     │                       (if registered)                 │
     │                              │                        │
     │                    5. Send Notification               │
     │                       (async)                         │
     │                              │──────────────────────> │
     │                              │ sendNotification()     │
     │                              │ "Welcome Back!"        │
     │                              │<────────────────────── │
     │                              │ Message ID             │
     │                              │                        │
     │              6. Log in Database                        │
     │                 fcm_token + timestamp                 │
     │                              │                        │
     │ 7. Return 200 + Tokens       │                        │
     │<─────────────────────────────│                        │
     │   (accessToken,              │                        │
     │    refreshToken)             │                        │
     │                              │                        │
     │ 8. Store Tokens (localStorage/cookie)                 │
     │ 9. Notification Received on Device ◄────────────────┐ │
     │    "Welcome back! You have successfully logged in"    │ │
     │                                                        │ │
     │                                         (FCM Service) │
     │
     └─────────────────────────────────────────────────────────┘

Key Points:
✓ Notification is sent ASYNCHRONOUSLY (doesn't delay login)
✓ If FCM fails, login still succeeds
✓ Tokens are stored in database with timestamp
✓ User sees notification in browser/app within 1-2 seconds
```

---

## Logout Flow with FCM

```
┌─────────────────────────────────────────────────────────────────┐
│                        LOGOUT FLOW                              │
└─────────────────────────────────────────────────────────────────┘

User Browser                  Auth Service              Firebase
     │                              │                        │
     │ 1. POST /logout              │                        │
     │    (with accessToken)        │                        │
     │─────────────────────────────>│                        │
     │                              │                        │
     │                    2. Verify JWT Token                 │
     │                       (check signature)               │
     │                              │                        │
     │                    3. Get FCM Token from DB            │
     │                       (using user ID)                  │
     │                              │                        │
     │                    4. Send Logout Notification         │
     │                       (async)                          │
     │                              │──────────────────────> │
     │                              │ sendNotification()     │
     │                              │ "You have logged out"  │
     │                              │<────────────────────── │
     │                              │ Message ID             │
     │                              │                        │
     │              5. Delete FCM Token from DB               │
     │                 DELETE fcm_token WHERE user_id=X      │
     │                              │                        │
     │              6. Clear Redis Sessions                   │
     │                 DEL session:<user_id>                 │
     │                 DEL refresh:<user_id>                 │
     │                              │                        │
     │              7. Clear Cookies                          │
     │                 (accessToken, refreshToken)           │
     │                              │                        │
     │ 8. Return 200 Success        │                        │
     │<─────────────────────────────│                        │
     │   {message: "Successfully    │                        │
     │     logged out"}             │                        │
     │                              │                        │
     │ 9. Notification Received ◄────────────────────────┐   │
     │    "You have been logged out"                        │   │
     │    FCM token deleted from DB                    (FCM) │   │
     │                                                        │   │
     └─────────────────────────────────────────────────────────┘

Key Points:
✓ Notification sent before token deletion
✓ Token is deleted from database immediately
✓ All sessions cleared (Redis, Cookies)
✓ If FCM fails, logout still completes
✓ User cannot use old tokens after logout
```

---

## FCM Token Registration Flow

```
┌─────────────────────────────────────────────────────────────────┐
│              FCM TOKEN REGISTRATION FLOW                         │
└─────────────────────────────────────────────────────────────────┘

User Browser                  Auth Service              Database
     │                              │                        │
     │ 1. Request Notification Perm │                        │
     │    (browser dialog)          │                        │
     │─────────────────────┐        │                        │
     │                    │        │                        │
     │ 2. User Grants Perm │        │                        │
     │<────────────────────┘        │                        │
     │                              │                        │
     │ 3. Get FCM Token from Firebase                        │
     │    (via Firebase SDK)        │                        │
     │ ════════════════════════════>│                        │
     │    (Firebase SDK internal)   │                        │
     │                              │                        │
     │ 4. POST /fcm/register-token  │                        │
     │    + Bearer Token (JWT)      │                        │
     │    + FCM Token               │                        │
     │─────────────────────────────>│                        │
     │                              │                        │
     │                    5. Verify JWT                       │
     │                       (check session)                  │
     │                              │                        │
     │                    6. Extract User ID from JWT         │
     │                              │                        │
     │                    7. Update Database                  │
     │                              │──────────────────────> │
     │                              │ UPDATE users SET       │
     │                              │   fcm_token = $1,      │
     │                              │   fcm_token_updated_at │
     │                              │   = NOW()              │
     │                              │ WHERE id = $2          │
     │                              │<────────────────────── │
     │                              │ Success                │
     │                              │                        │
     │ 8. Return 200 Success        │                        │
     │<─────────────────────────────│                        │
     │ {message: "FCM token         │                        │
     │  registered successfully",   │                        │
     │  data: {...}}                │                        │
     │                              │                        │
     │ 9. Token Stored in Database  │                        │
     │    Ready for notifications   │                        │
     │                              │                        │

Key Points:
✓ Token persisted across browser refreshes
✓ Each device has its own token
✓ Token can be updated anytime
✓ Timestamp tracks when token was last updated
✓ User must be authenticated (JWT required)
```

---

## Data Flow Diagram

```
┌──────────────────────────────────────────────────────────────┐
│              FCM SYSTEM DATA FLOW                            │
└──────────────────────────────────────────────────────────────┘

                    ┌─────────────────┐
                    │  User Logs In   │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  JWT Generated  │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────────────────┐
                    │  User Registers FCM Token   │
                    │  (POST /fcm/register-token) │
                    └────────┬────────────────────┘
                             │
                             ▼
                    ┌─────────────────────────────┐
                    │  Store in Database:         │
                    │  users.fcm_token = "abc.." │
                    │  fcm_token_updated_at = now │
                    └────────┬────────────────────┘
                             │
                    ┌────────┴──────────┐
                    │                   │
                    ▼                   ▼
          ┌─────────────────┐  ┌─────────────────┐
          │  User Logs Out  │  │  Next Login     │
          └────────┬────────┘  └────────┬────────┘
                   │                    │
                   ▼                    ▼
          ┌────────────────────────────────┐
          │ Get FCM Token from Database    │
          │ (SELECT fcm_token FROM users)  │
          └────────┬─────────────────────┘
                   │
                   ▼
          ┌─────────────────────────────────┐
          │ Send FCM Notification           │
          │ (firebase-admin messaging.send) │
          └────────┬───────────────────────┘
                   │
                   ▼
          ┌─────────────────────────────────┐
          │ Firebase Cloud Delivery         │
          │ to Device                       │
          └────────┬───────────────────────┘
                   │
                   ▼
          ┌─────────────────────────────────┐
          │ User Receives Notification      │
          │ on Device/Browser               │
          └─────────────────────────────────┘
```

---

## Component Interaction Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    FCM COMPONENTS                               │
└─────────────────────────────────────────────────────────────────┘

Frontend                                Backend
┌──────────────────┐                 ┌──────────────────────────┐
│ Firebase SDK     │                 │ firebaseAdmin.js         │
│ - getToken()     │ ◄──────────────>│ - initializeFirebase()  │
│ - onMessage()    │                 │ - getMessaging()        │
│ - requestPerm()  │                 └──────────────────────────┘
└──────────────────┘                           ▲
         ▲                                      │
         │                                      │ Uses
         │                                      ▼
    Send │                          ┌──────────────────────────┐
   Token │                          │ fcmService.js            │
         │                          │ - sendNotification()    │
         │                          │ - sendLoginNotif..()    │
         │                          │ - sendLogoutNotif..()   │
         ▼                          └──────────────────────────┘
┌──────────────────┐                           ▲
│ Auth Routes      │                           │ Calls
│ /fcm/register    │◄──────────────┐           │
│ /fcm/token       │               │ Calls    │
│ /login           │               └──────────┤
│ /logout          │                          │
└──────────────────┘                ┌─────────▼──────────────┐
         ▲                          │ fcmTokenManager.js     │
         │                          │ - updateToken()       │
    Auth │                          │ - getUserToken()      │
   Check │                          │ - deleteToken()       │
         │                          │ - addColumn()         │
         ▼                          └──────────┬────────────┘
┌──────────────────┐                         │
│ verifySession    │                         │
│ Middleware       │                         │
└──────────────────┘                    Uses Database
                                        PostgreSQL
                                        ┌──────────────┐
                                        │ users table  │
                                        │ - fcm_token  │
                                        │ - updated_at │
                                        └──────────────┘
```

---

## Technology Stack

```
┌─────────────────────────────────────────────────────────────┐
│                  TECHNOLOGY STACK                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ FRONTEND:                                                   │
│ ├─ React/Next.js                                           │
│ ├─ Firebase SDK (web)                                      │
│ └─ Service Worker (for background messages)               │
│                                                             │
│ BACKEND:                                                    │
│ ├─ Node.js / Express                                       │
│ ├─ firebase-admin@13.6.0                                   │
│ ├─ PostgreSQL (user data + FCM tokens)                    │
│ ├─ Redis (session management)                             │
│ ├─ jsonwebtoken (JWT auth)                                │
│ └─ bcrypt (password hashing)                              │
│                                                             │
│ CLOUD SERVICES:                                            │
│ ├─ Firebase Cloud Messaging (FCM)                         │
│ ├─ Firebase Admin SDK                                      │
│ └─ Google Cloud (project hosting)                         │
│                                                             │
│ PROJECT ID:                                                 │
│ └─ expensetracker-2759d                                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Request/Response Examples

### 1. Login (with FCM notification)

**Request:**
```
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

**Backend Process:**
```
1. Validate email & password
2. Get FCM token from database
3. Send notification asynchronously
4. Generate JWT tokens
5. Return response
```

**Response:**
```
HTTP 200 OK
{
  "message": "Logged In",
  "accessToken": "eyJhbGc...",
  "refreshToken": "eyJhbGc..."
}
```

**Notification Sent to User:**
```
Title: "Login Successful"
Body: "Welcome back User! You have successfully logged in."
Data: {
  "type": "login",
  "userId": "2b40d5bd-8344-430c-ba57-...",
  "timestamp": "2026-01-30T12:34:56.789Z"
}
```

---

### 2. Register FCM Token

**Request:**
```
POST /api/v1/auth/fcm/register-token
Authorization: Bearer eyJhbGc...
Content-Type: application/json

{
  "token": "fB...MCv"
}
```

**Backend Process:**
```
1. Verify JWT token (extract user ID)
2. Validate FCM token format
3. Update database with token
4. Return success
```

**Response:**
```
HTTP 200 OK
{
  "message": "FCM token registered successfully",
  "data": {
    "id": "2b40d5bd-8344-430c-ba57-...",
    "fcm_token": "fB...MCv"
  }
}
```

---

### 3. Logout (with FCM notification)

**Request:**
```
POST /api/v1/auth/logout
Cookie: accessToken=eyJhbGc...
```

**Backend Process:**
```
1. Verify access token
2. Get FCM token from database
3. Send logout notification
4. Delete FCM token from database
5. Clear Redis sessions
6. Return response
```

**Response:**
```
HTTP 200 OK
{
  "message": "Successfully logged out"
}
```

**Notification Sent to User:**
```
Title: "Logged Out"
Body: "You have been logged out. See you next time!"
Data: {
  "type": "logout",
  "timestamp": "2026-01-30T12:34:56.789Z"
}
```

---

## Summary

This FCM integration provides:

✅ **Automatic Notifications** - No manual trigger needed
✅ **Secure** - JWT authentication required for token management
✅ **Reliable** - Non-blocking, async operations
✅ **Persistent** - Tokens stored in database
✅ **Scalable** - Ready for multicast notifications
✅ **Fault-tolerant** - FCM failures don't break login/logout

All flows are designed to work seamlessly and provide excellent user experience! 🚀
