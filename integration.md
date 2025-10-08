# Redmine Gateway Integration Guide

## Overview

The Redmine Gateway is a secure authentication and API proxy service that provides OAuth 2.0 authentication for Redmine applications. It acts as a single sign-on gateway, handles security middleware (CORS, CSRF, rate limiting), and proxies API requests to Redmine with automatic API key management.

## Container Setup

### Prerequisites

- Docker and Docker Compose
- PostgreSQL database (for user authentication)
- Redis (for session management and caching)
- Redmine instance with REST API enabled

### Environment Variables

Copy `.env.example` or `.env.security.example` to `.env` and configure the following variables:

#### Server Configuration
- `SERVER_HOST`: Server bind address (default: `0.0.0.0`)
- `SERVER_PORT`: Server port (default: `8080`)
- `SERVER_MODE`: Server mode - `development` or `production` (default: `development`)
- `SERVER_BASE_URL`: Base URL for the service (default: `http://localhost:8080`)
- `SERVER_READ_TIMEOUT`: Read timeout in seconds (default: `30s`)
- `SERVER_WRITE_TIMEOUT`: Write timeout in seconds (default: `30s`)

#### Database Configuration
- `DATABASE_URL`: PostgreSQL connection string (default: `postgres://postgres:password@localhost:5432/redmine?sslmode=disable`)

#### Redis Configuration
- `REDIS_ADDRESS`: Redis server address (default: `localhost:6379`)
- `REDIS_PASSWORD`: Redis password (default: empty)
- `REDIS_DB`: Redis database number (default: `0`)

#### JWT Configuration
- `JWT_SECRET`: JWT signing secret (must be changed in production, at least 32 characters)
- `JWT_ACCESS_TOKEN_DURATION`: Access token duration (default: `15m`)
- `JWT_REFRESH_TOKEN_DURATION`: Refresh token duration (default: `168h` - 7 days)
- `JWT_ISSUER`: JWT issuer URL (default: `http://localhost:8080`)

#### OAuth Configuration
- `OAUTH_ISSUER`: OAuth issuer URL (default: `http://localhost:8080`)
- `OAUTH_AUTHORIZATION_CODE_TTL`: Authorization code TTL (default: `10m`)
- `OAUTH_CLIENT_ID`: OAuth client ID (default: `redmine-frontend`)
- `OAUTH_CLIENT_NAME`: OAuth client name (default: `Redmine Frontend`)
- `OAUTH_CLIENT_SECRET`: OAuth client secret (leave empty for public clients)
- `OAUTH_CLIENT_TYPE`: Client type - `public` or `confidential` (default: `confidential`, recommended: `public`)
  - **`public`**: For client applications that cannot securely store secrets (SPAs, mobile apps, frontend JavaScript). Uses PKCE instead of client_secret for security. No client_secret required.
  - **`confidential`**: For server-side applications that can securely store secrets (backend services, server-rendered apps). Requires client_secret for authentication.
  - **Use `public`** for: Single Page Applications (Vue, React, Angular), mobile apps, any frontend-only applications
  - **Use `confidential`** for: Backend services, server-side web applications, microservices with secure storage
- `OAUTH_REDIRECT_URI`: OAuth redirect URI (default: `http://localhost:3000/auth/callback`)

#### Redmine Configuration
- `REDMINE_BASE_URL`: Redmine instance base URL (default: `http://localhost:3000`)
- `REDMINE_TEST_API_KEY`: Redmine admin API key for testing (optional)
- `REDMINE_TIMEOUT`: Redmine API timeout (default: `30s`)

#### Security Configuration
- `CORS_ORIGINS`: Comma-separated list of allowed CORS origins (default: `http://localhost:3000`)
- `SECURE_COOKIES`: Whether to use secure cookies (HTTPS only) (default: `false`)
- `CSRF_SECRET`: CSRF protection secret (must be changed in production, at least 32 characters)
- `SESSION_TIMEOUT`: Session timeout duration (default: `15m`)
- `MAX_USERNAME_LENGTH`: Maximum username length (default: `100`)
- `MAX_PASSWORD_LENGTH`: Maximum password length (default: `255`)

#### Rate Limiting Configuration
- `RATE_LIMIT_LOGIN_ATTEMPTS`: Maximum login attempts per window (default: `5`)
- `RATE_LIMIT_LOGIN_WINDOW`: Login rate limit window (default: `15m`)
- `RATE_LIMIT_API_REQUESTS`: Maximum API requests per window (default: `1000`)
- `RATE_LIMIT_API_WINDOW`: API rate limit window (default: `1h`)
- `RATE_LIMIT_CLEANUP_INTERVAL`: Rate limit cleanup interval (default: `1h`)

#### Logging Configuration
- `LOG_LEVEL`: Log level - `debug`, `info`, `warn`, `error` (default: `info`)
- `LOG_FORMAT`: Log format - `json` or `text` (default: `json`)

### Docker Commands

```bash
# Build the container
docker build -t redmine-gateway .

# Run the container
docker run -d \
  --name redmine-gateway \
  -p 8080:8080 \
  --env-file .env \
  redmine-gateway

# Or using docker-compose
docker-compose up -d
```

### Health Check

The service includes a health check endpoint at `/health` and a Redmine connection validation at `/redmine/status`.

## Integration

### Service Base URLs

- **Main Service URL**: `http://localhost:8080` (configurable via `SERVER_BASE_URL`)
- **Auth Service URL**: Same as main service URL (endpoints under `/auth`)
- **API Proxy URL**: Same as main service URL (endpoints under `/api`)

### Authentication Endpoints

#### Secure Authentication (Session-based)

- `GET /auth/login` - Display secure login page
- `POST /auth/login` - Authenticate user and create session
  - Request body: `{"username": "string", "password": "string"}`
  - Response: `{"authenticated": true, "session_token": "string", "user_id": number, "expires_in": number, "csrf_token": "string"}`
- `POST /auth/logout` - Destroy current session
- `GET /auth/session` - Validate current session
  - Response: `{"authenticated": true, "user_id": number, "username": "string", "expires_in": number}`

#### OAuth 2.0 Endpoints

- `GET /oauth/authorize` - OAuth 2.0 authorization endpoint
  - Parameters: `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state`, `code_challenge`, `code_challenge_method`
- `GET /oauth/login` - Display OAuth login form (legacy)
- `POST /oauth/login` - Process OAuth login (legacy)
- `POST /oauth/token` - Exchange authorization code for access token
  - Grant types: `authorization_code`, `refresh_token`
  - Request: `grant_type`, `code`/`refresh_token`, `redirect_uri`, `client_id`, `client_secret`, `code_verifier`
  - Response: `{"access_token": "string", "token_type": "Bearer", "expires_in": number, "refresh_token": "string"}`
- `GET /oauth/userinfo` - Get user information (requires access token)
  - Response: `{"sub": "string", "name": "string", "email": "string", "preferred_username": "string"}`

### API Proxy Endpoints

All API endpoints require a valid OAuth 2.0 access token in the `Authorization: Bearer <token>` header.

#### User Endpoints
- `GET /api/user` - Get current authenticated user information

#### Projects
- `GET /api/projects` - List projects
- `POST /api/projects` - Create project
- `GET /api/projects/:id` - Get project details
- `PUT /api/projects/:id` - Update project
- `DELETE /api/projects/:id` - Delete project
- `GET /api/projects/:id/memberships` - Get project memberships

#### Issues
- `GET /api/issues` - List issues
- `POST /api/issues` - Create issue
- `GET /api/issues/:id` - Get issue details
- `PUT /api/issues/:id` - Update issue
- `DELETE /api/issues/:id` - Delete issue

#### Users
- `GET /api/users` - List users
- `GET /api/users/current` - Get current user
- `GET /api/users/:id` - Get user details

#### Time Entries
- `GET /api/time_entries` - List time entries
- `POST /api/time_entries` - Create time entry
- `GET /api/time_entries/:id` - Get time entry details
- `PUT /api/time_entries/:id` - Update time entry
- `DELETE /api/time_entries/:id` - Delete time entry

#### Attachments & Uploads
- `POST /api/uploads` - Upload file
- `GET /api/attachments/:id` - Get attachment

#### Metadata
- `GET /api/trackers` - List trackers
- `GET /api/issue_statuses` - List issue statuses
- `GET /api/issue_priorities` - List issue priorities
- `GET /api/enumerations` - List enumerations
- `GET /api/enumerations/issue_priorities` - List issue priorities enumeration
- `GET /api/custom_fields` - List custom fields

### Diagnostic Endpoints

- `GET /diagnostic` - Comprehensive diagnostic check
- `GET /health` - Service health check
- `GET /redmine/status` - Redmine connection status

### OAuth 2.0 Flow Example

```mermaid
sequenceDiagram
    autonumber
    participant Client as Your App
    participant Auth as Redmine Gateway
    participant User as User
    participant API as Redmine API

    Client->>Auth: GET /oauth/authorize (with params)
    Auth->>Auth: Check for auth_session cookie
    Auth->>Client: Redirect to /auth/login (if no session)
    User->>Auth: POST /auth/login (authenticate)
    Auth->>Auth: Create session & set cookie
    Auth->>Client: Redirect back to /oauth/authorize
    Auth->>Auth: Generate authorization code
    Auth->>Client: Redirect with authorization code
    Client->>Auth: POST /oauth/token (exchange code)
    Auth->>Client: Return access token
    Client->>Auth: API request with Bearer token
    Auth->>API: Proxied API request
    API->>Auth: API response
    Auth->>Client: API response
```

#### Step-by-Step Integration Guide

**Step 1: Initiate Authorization Request**  
*What you implement:* Redirect user to the authorization endpoint  
*Purpose:* Start the OAuth flow and request user permission  

**Example Request (Browser redirect):**
```
GET https://your-gateway.com/oauth/authorize?
    response_type=code&
    client_id=your-client-id&
    redirect_uri=https://your-app.com/callback&
    scope=read%20write&
    state=xyz123&
    code_challenge=challenge_value&
    code_challenge_method=S256
```

**Parameters:**
- `response_type=code`: Request authorization code grant
- `client_id`: Your registered client ID
- `redirect_uri`: Must match registered redirect URI
- `scope`: Requested permissions (space-separated)
- `state`: CSRF protection (your app should validate this)

**Step 2: Gateway Session Check & Authentication**  
*What happens:* Gateway checks for existing authentication session  
*What you implement:* Nothing - the gateway manages this  

If no valid session exists, the gateway redirects the user to `/auth/login` with a `return_to` parameter containing the original OAuth request. The user authenticates using their Redmine credentials via a secure login form.

**Step 3: Session Creation**  
*What happens:* After successful authentication, gateway creates secure session  
*What you implement:* Nothing - the gateway manages this  

The gateway validates credentials against the PostgreSQL database, creates a secure session in Redis, and sets an `auth_session` cookie. The user is then redirected back to the original `/oauth/authorize` request.

**Step 4: Authorization Code Generation**  
*What happens:* Gateway generates and returns authorization code  
*What you implement:* Nothing - the gateway manages this  

With a valid session, the gateway generates a secure authorization code (stored in Redis with 10-minute expiry), cleans up the session cookie, and redirects the user back to your application's callback URL.

**Step 5: Authorization Code Redirect**  
*What you implement:* Handle the callback with authorization code  
*Purpose:* Receive the temporary authorization code  

**Example Response (User redirected to your callback):**
```
https://your-app.com/callback?
    code=abc123def456&
    state=xyz123
```

**What to do:**
- Validate the `state` parameter matches what you sent
- Extract the `code` parameter for the next step
- Handle errors if present (e.g., `error=access_denied`)

**Step 6: Exchange Code for Access Token**  
*What you implement:* Server-side token exchange  
*Purpose:* Convert authorization code to access token  

**Example Request (Server-side POST):**
```bash
curl -X POST https://your-gateway.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=abc123def456" \
  -d "redirect_uri=https://your-app.com/callback" \
  -d "client_id=your-client-id" \
  -d "code_verifier=verifier_value"
```

*Note: For public clients with PKCE, `client_secret` is not required.*

**Example Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "refresh_abc123...",
  "scope": "read write"
}
```

**What to do:**
- Store the `access_token` securely (never in client-side storage)
- Store the `refresh_token` for long-term access
- Note the `expires_in` seconds (15 minutes default)

**Step 7: Make API Calls**  
*What you implement:* Include Bearer token in API requests  
*Purpose:* Access protected Redmine API resources  

**Example API Request:**
```bash
curl -X GET https://your-gateway.com/api/projects \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Example API Response:**
```json
{
  "projects": [
    {
      "id": 1,
      "name": "My Project",
      "identifier": "my-project",
      "description": "Project description"
    }
  ]
}
```

**Token Refresh (when needed):**
```bash
curl -X POST https://your-gateway.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=refresh_abc123..." \
  -d "client_id=your-client-id"
```

*Note: For public clients, `client_secret` is not required for token refresh.*

#### Implementation Checklist

- [ ] Configure OAuth client as `public` type in gateway settings
- [ ] Implement PKCE challenge generation in frontend (ensure SHA-256 + base64url encoding)
- [ ] Make PKCE generation functions `async` and properly await them
- [ ] Include `code_challenge` and `code_challenge_method=S256` in authorization requests
- [ ] Send `code_verifier` instead of `client_secret` in token exchange
- [ ] Store PKCE verifier securely in sessionStorage (not localStorage)
- [ ] Ensure client ID matches between frontend configuration and server settings
- [ ] Handle token refresh without client_secret for public clients
- [ ] Test OAuth flow with PKCE end-to-end
- [ ] Validate `state` parameter for CSRF protection
- [ ] Handle OAuth errors gracefully

### Security Features

- **CORS Protection**: Configurable allowed origins
- **CSRF Protection**: Automatic CSRF token validation
- **Rate Limiting**: Configurable limits for login attempts and API requests
- **Secure Cookies**: HTTP-only, secure cookies for sessions
- **Input Validation**: Sanitization and length limits for user inputs
- **Session Management**: Secure session handling with Redis
- **Security Headers**: Comprehensive security headers middleware
- **PKCE Support**: Proof Key for Code Exchange for public clients (no client_secret required)

### Error Handling

The service returns standard HTTP status codes and JSON error responses:

```json
{
  "error": "error_code",
  "error_description": "Human-readable description"
}
```

Common error codes:
- `invalid_request`: Bad request parameters
- `invalid_credentials`: Authentication failed
- `invalid_session`: Session validation failed
- `invalid_client`: Unknown OAuth client or mismatched client credentials
- `invalid_grant`: Authorization code expired, invalid, or PKCE verification failed
- `server_error`: Internal server error
- `rest_api_disabled`: Redmine REST API not enabled

### Common Issues & Troubleshooting

#### "Unknown OAuth client" Error
**Cause**: Client ID mismatch between frontend and server configuration
**Solution**: Ensure `OAUTH_CLIENT_ID` in server matches the client ID used in frontend requests

#### "PKCE verification failed" Error
**Cause**: PKCE code challenge/verifier mismatch due to improper generation
**Solutions**:
- Ensure PKCE generation functions are `async` and properly awaited
- Use proper SHA-256 + base64url encoding (not plain base64)
- Store verifier in sessionStorage (survives page navigation)
- Don't regenerate PKCE values between authorization and token exchange

#### Authentication Loops (Login → Logout → Login)
**Cause**: Token exchange failing, causing frontend to clear tokens and restart auth
**Solutions**:
- Check OAuth service logs for specific token exchange errors
- Verify client type is set to `public` for PKCE flows
- Ensure `code_verifier` is sent instead of `client_secret` for public clients

#### Environment Variable Issues
**Common mistakes**:
- Using `AUTH_CLIENT_TYPE` instead of `OAUTH_CLIENT_TYPE` 
- Client ID mismatch between `.env.production` and server configuration
- Missing environment variables causing defaults to be used</content>
<parameter name="filePath">C:\code\github\gmb\test\redmine-gateway\integration.md