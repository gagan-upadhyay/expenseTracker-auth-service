# Expense Tracker - Auth Service

A comprehensive authentication and authorization service for the Expense Tracker application, built with Node.js and Express. This service handles user registration, login, OAuth integration, and secure session management.

## Features

- **User Authentication**
  - Email/password registration and login
  - Password hashing with bcrypt
  - JWT token-based authentication
  - OAuth 2.0 support (Google authentication)

- **Session Management**
  - Redis-backed session storage
  - Secure cookie handling
  - Session timeout configuration
  - CSRF protection


- **Security**
  - Helmet.js for HTTP headers security
  - Rate limiting middleware
  - CORS configuration
  - Request validation with express-validator
  - Password strength validation

- **Database**
  - PostgreSQL for user and session data
  - Redis for caching and session management
  - Kafka for event streaming

- **Monitoring & Logging**
  - Winston logging system
  - Request logging with Morgan
  - Health check endpoints
  - Graceful shutdown handling

## Tech Stack

- **Runtime:** Node.js (ES Modules)
- **Framework:** Express.js v5.1.0
- **Authentication:** Passport.js, JWT, OAuth 2.0
- **Database:** PostgreSQL, Redis
- **Messaging:** Kafka
- **Security:** Helmet, bcrypt
- **Logging:** Winston, Morgan
- **Testing:** Jest, Supertest

## Project Structure

```
├── config/                          # Configuration files
│   ├── dbconnection.js             # PostgreSQL connection pool
│   ├── helmet.config.js            # Security headers config
│   ├── logger.js                   # Winston logger setup
│   └── redisConnection.js          # Redis client configuration
├── src/
│   ├── controllers/
│   │   ├── authController.js       # Authentication logic
│   ├── model/
│   │   └── userModel.js            # User database model
│   ├── routes/
│   │   └── AuthRoutes.js           # Auth endpoint definitions
│   ├── services/
│   │   └── authService.js          # Authentication business logic
├── middleware/
│   ├── rateLimiter.js              # Rate limiting
│   ├── sessionMiddleware.js        # Session handling
│   ├── validator.js                # Request validation
│   └── verifySession.js            # Session verification
├── utils/
│   ├── cookiesUtils.js             # Cookie management
│   ├── emailValidator.js           # Email validation
│   ├── mailer.js                   # Email sending
│   ├── OAuth.js                    # OAuth utilities
│   ├── pgUtils.js                  # PostgreSQL utilities
│   ├── redisUtility.js             # Redis utilities
│   ├── setupGracefulShutdown.js    # Server shutdown
│   ├── setupHealthcheckUp.js       # Health check
│   └── tokenSetter.js              # Token management
├── __tests__/                       # Test files
│   └── APIEndpoint.test.js
├── index.js                         # Application entry point
├── package.json                     # Dependencies and scripts
└── README.md                        # This file
```

## Environment Variables

Create a `.env` file in the root directory with the following variables:

```env
# Server Configuration
PORT=5000
NODE_ENV=development

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/expensetracker
DB_USER=postgres
DB_HOST=localhost
DB_DATABASE=expensetracker
DB_PASSWORD=your_password
DB_PORT=5432

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# JWT
JWT_SECRET=your_jwt_secret_key
JWT_EXPIRY=7d

# Session
SESSION_SECRET=your_session_secret
SESSION_TIMEOUT=3600000

# Google OAuth
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_CALLBACK_URL=http://localhost:5000/api/v1/auth/google/callback

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASSWORD=your_app_password

# CORS
CORS_ORIGIN=http://localhost:3000

# Kafka
KAFKA_BROKERS=localhost:9092
```

## Installation

1. **Clone the repository:**
```bash
git clone <repository-url>
cd expenseTracker-auth-service
```

2. **Install dependencies:**
```bash
npm install
```

3. **Set up environment variables:**
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. **Initialize the database:**
```bash
npm run db:init
```

5. **Start Redis:**
```bash
redis-server
```

6. **Start the development server:**
```bash
npm run dev
```

The server will start on `http://localhost:5000`

## API Endpoints

### Authentication

- `POST /api/v1/auth/register` - Register a new user
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/logout` - User logout
- `POST /api/v1/auth/refresh-token` - Refresh JWT token
- `GET /api/v1/auth/google` - Google OAuth login
- `GET /api/v1/auth/google/callback` - Google OAuth callback


### User Management

- `GET /api/v1/auth/user` - Get current user profile
- `PUT /api/v1/auth/user` - Update user profile
- `DELETE /api/v1/auth/user` - Delete user account

### Health Check

- `GET /api/v1/health` - Service health status

## Scripts

```bash
# Development
npm run dev              # Start with nodemon (auto-reload)

# Testing
npm run test-windows    # Run tests on Windows
npm run test-unix       # Run tests on Unix/Linux/Mac

# Production
npm start               # Start the server
```

## Testing

### Using Postman

1. Import the Postman collection from `POSTMAN_TESTING.md`
2. Set up the environment with your configuration
3. Run the requests in sequence

### Using Jest

```bash
npm run test-windows    # Windows
npm run test-unix       # Unix/Linux/Mac
```

Test files are located in `__tests__/` directory.

## Database Schema

### Users Table
```sql
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(255) UNIQUE NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255),
  google_id VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  is_active BOOLEAN DEFAULT true
);
```



## Security Considerations

1. **Password Security**
   - Passwords are hashed using bcrypt with salt rounds of 10
   - Minimum password requirements enforced during registration

2. **JWT Tokens**
   - Short expiry times (default: 15 minutes)
   - Refresh token rotation recommended
   - Tokens are invalidated on logout

3. **CORS**
   - Limited to configured origins only
   - Credentials required for cross-origin requests

4. **Rate Limiting**
   - Applied to authentication endpoints
   - Prevents brute force attacks

5. **Session Security**
   - Secure session storage in Redis
   - HTTP-only cookies
   - CSRF protection enabled

## Error Handling

The service returns standard HTTP status codes:

- `200 OK` - Successful request
- `201 Created` - Resource created successfully
- `400 Bad Request` - Invalid input
- `401 Unauthorized` - Authentication failed
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `429 Too Many Requests` - Rate limit exceeded
- `500 Internal Server Error` - Server error

## Logging

Logs are managed using Winston logger and stored in:
- Console output (development)
- `logs/error.log` - Error logs
- `logs/combined.log` - All logs

Configure log levels in `config/logger.js`

## Performance Optimization

- Response compression enabled
- Redis caching for sessions
- Connection pooling for PostgreSQL
- Request timeout handling
- Graceful shutdown implementation

## Troubleshooting

### Database Connection Issues
- Verify PostgreSQL is running
- Check `DATABASE_URL` in `.env`
- Ensure database exists and credentials are correct

### Redis Connection Issues
- Verify Redis is running on the correct port
- Check `REDIS_HOST` and `REDIS_PORT` in `.env`
- Verify no authentication required or password is set


### Email Sending Issues
- Verify SMTP credentials are correct
- Check if "Less secure app access" is enabled for Gmail
- Use app-specific password for Gmail accounts

## Contributing

1. Create a feature branch (`git checkout -b feature/AmazingFeature`)
2. Commit your changes (`git commit -m 'Add AmazingFeature'`)
3. Push to the branch (`git push origin feature/AmazingFeature`)
4. Open a Pull Request

## License

This project is licensed under the ISC License - see the package.json file for details.

## Author

**Gagan Upadhyay**

## Support

For issues, questions, or suggestions, please create an issue in the repository or contact the development team.

## Additional Documentation

- [Testing Guide](./TESTING_GUIDE.md)
- [Postman Testing](./POSTMAN_TESTING.md)
- [Deployment Checklist](./DEPLOYMENT_CHECKLIST.md)

---

**Last Updated:** February 2026
