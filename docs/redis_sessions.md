# Redis Session Types in Redmine Gateway

This document explains the different types of sessions and temporary data stored in Redis by the Redmine Gateway application.

## Overview

The application uses Redis for storing various types of session data and temporary information. Each type serves a specific security or workflow purpose in the authentication and authorization flow.

## 1. Authentication Sessions (`auth_session:*`)

### Purpose
Stores authenticated user sessions after successful login and 2FA verification.

### Key Format
```
auth_session:{session_token}
```

### Data Structure
```json
{
  "user_id": 123,
  "username": "john.doe",
  "client_ip": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "created_at": "2025-10-24T12:35:09Z",
  "last_accessed": "2025-10-24T12:35:09Z",
  "csrf_token": "abc123...",
  "return_to": "/oauth/authorize?client_id=..."
}
```

### TTL (Time To Live)
- Default: 15 minutes (900 seconds)
- Configurable via `SESSION_TIMEOUT`

### Security Features
- **IP Address Validation**: Session is invalidated if client IP changes
- **User Agent Validation**: Session is invalidated if user agent changes
- **CSRF Protection**: Each session has an associated CSRF token
- **Automatic Expiration**: Redis TTL ensures sessions don't persist indefinitely

### Usage Flow
1. Created after successful login + 2FA verification
2. Used for subsequent API requests via `SessionAuthMiddleware`
3. Destroyed on logout or expiration
4. Can store `return_to` URL for OAuth flow continuation

---

## 2. 2FA Challenge Sessions (`twofa:session:*`)

### Purpose
Manages temporary 2FA verification challenges during authentication flow.

### Key Format
```
twofa:session:{uuid_token}
```

### Data Structure (Redis Hash)
```
user_id: "123"
username: "john.doe"
ip: "192.168.1.100"
attempts: "0"
created_at: "2025-10-24T12:35:09Z"
enrollment_mode: "false"
```

### TTL (Time To Live)
- Default: 5 minutes (300 seconds)
- Configurable via `TWOFA_SESSION_TIMEOUT`

### Security Features
- **IP Address Validation**: Enhanced validation with trusted proxy support
- **Attempt Tracking**: Failed attempts are counted and limited
- **Account Lockout**: After max attempts, account gets locked
- **UUID Tokens**: Cryptographically secure random tokens

### Usage Flow
1. Created when user needs 2FA verification (login or post-password-change)
2. User submits TOTP code or backup code
3. Session tracks attempts and validates codes
4. Destroyed after successful verification or expiration
5. Triggers account lockout on too many failed attempts

---

## 3. 2FA Attempt Counters (`twofa:attempts:*`)

### Purpose
Tracks failed 2FA verification attempts per session.

### Key Format
```
twofa:attempts:{uuid_token}
```

### Data Structure
Simple integer counter stored as string:
```
"3"
```

### TTL (Time To Live)
- Same as 2FA session: 5 minutes (300 seconds)

### Security Features
- **Rate Limiting**: Prevents brute force attacks on 2FA codes
- **Automatic Cleanup**: Expires with the session

### Usage Flow
1. Incremented on each failed 2FA verification attempt
2. Checked against `TWOFA_MAX_ATTEMPTS` (default: 3)
3. Triggers account lockout when limit exceeded
4. Reset when session expires

---

## 4. Account Lockout Flags (`twofa:locked:*`)

### Purpose
Temporarily locks user accounts after too many failed 2FA attempts.

### Key Format
```
twofa:locked:{user_id}
```

### Data Structure
Simple flag:
```
"1"
```

### TTL (Time To Live)
- Default: 1 hour (3600 seconds)
- Configurable via `TWOFA_LOCKOUT_DURATION`

### Security Features
- **Account Protection**: Prevents further login attempts during lockout
- **Automatic Unlock**: Lockout expires automatically

### Usage Flow
1. Set when user exceeds max 2FA attempts
2. Checked before allowing new 2FA sessions
3. Prevents login until lockout expires
4. Logged for security monitoring

---

## 5. Temporary Return URLs (`temp_return_to:*`)

### Purpose
Stores OAuth return URLs during the authentication flow when users need to change passwords.

### Key Format
```
temp_return_to:{temp_session_token}
```

### Data Structure
URL string:
```
"/oauth/authorize?client_id=lx-vue-app&response_type=code&redirect_uri=http%3A//localhost%3A3000/auth/callback&scope=read+write&state=xyz123"
```

### TTL (Time To Live)
- 10 minutes (600 seconds)

### Security Features
- **Single Use**: Deleted after first retrieval
- **Short Expiration**: Prevents URL accumulation

### Usage Flow
1. Created when user accesses login page with `return_to` parameter
2. Retrieved during password change to maintain OAuth flow
3. Used to redirect user back to OAuth authorization after password change
4. Cleaned up immediately after use

---

## 6. CSRF Tokens (`csrf:*`)

### Purpose
Stores CSRF tokens for protecting against Cross-Site Request Forgery attacks.

### Key Format
```
csrf:{csrf_token}
```

### Data Structure
Session ID string:
```
"ElP6epALV8kwGS2cnyJV5grBOY8juEP0clxJT3eq"
```

### TTL (Time To Live)
- 30 minutes

### Security Features
- **Single Use**: Token is deleted after validation
- **Session Binding**: Each token is tied to a specific session
- **Short Expiration**: Limits window for CSRF attacks

### Usage Flow
1. Generated when creating user sessions
2. Included in API responses and HTML forms
3. Validated on state-changing requests (POST, PUT, DELETE)
4. Destroyed after successful validation

---

## 7. Rate Limiting Counters

### Login Rate Limits (`rate_limit:login:*`)
```
rate_limit:login:{client_ip}
```
- Tracks failed login attempts
- TTL: Configurable window (default: 15 minutes)

### 2FA Rate Limits (`rate_limit:twofa:*`)
```
rate_limit:twofa:{client_ip}
```
- Tracks failed 2FA verification attempts
- TTL: Configurable window (default: 15 minutes)

### Purpose
Prevents brute force attacks on authentication endpoints.

### Security Features
- **IP-Based Limiting**: Rate limits per client IP
- **Automatic Reset**: Counters reset on successful authentication
- **Configurable Limits**: Adjustable via environment variables

---

## Session Lifecycle Summary

### Authentication Flow:
1. **Login Page** → Temp session created for return URL
2. **Login** → 2FA session created if 2FA required
3. **2FA Verification** → Auth session created on success
4. **API Requests** → Auth session validated via middleware
5. **Logout** → Auth session destroyed

### Password Change Flow:
1. **Login** → Password change required → Temp return URL stored
2. **Password Change** → 2FA session created if 2FA enabled
3. **2FA Verification** → Auth session created with return URL
4. **OAuth Redirect** → User continues to original OAuth flow

### Security Monitoring:
- All session creation/destruction events are logged
- Failed attempts trigger rate limiting and account lockouts
- IP/User-Agent validation prevents session hijacking
- Automatic cleanup prevents Redis bloat

## Configuration

All TTL values and limits are configurable via environment variables:
- `SESSION_TIMEOUT`: Auth session duration
- `TWOFA_SESSION_TIMEOUT`: 2FA session duration
- `TWOFA_LOCKOUT_DURATION`: Account lockout duration
- `TWOFA_MAX_ATTEMPTS`: Max failed 2FA attempts
- `RATE_LIMIT_*`: Rate limiting configuration

This multi-layered session management ensures security, prevents attacks, and maintains user experience across complex authentication flows.</content>
<parameter name="filePath">c:\code\github\gmb\test\redis_sessions.md