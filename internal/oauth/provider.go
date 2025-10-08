package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"a_go_oauth/internal/config"
	"a_go_oauth/internal/database"
	"a_go_oauth/internal/logger"
)

type Provider struct {
	cfg    *config.Config
	db     *database.PostgreSQL
	redis  *redis.Client
	logger *logger.Logger
}

type AuthorizationCode struct {
	Code        string    `json:"code"`
	ClientID    string    `json:"client_id"`
	UserID      int       `json:"user_id"`
	RedirectURI string    `json:"redirect_uri"`
	Scope       string    `json:"scope"`
	ExpiresAt   time.Time `json:"expires_at"`
	Challenge   string    `json:"challenge,omitempty"` // PKCE code challenge
	Method      string    `json:"method,omitempty"`    // PKCE code challenge method
}

// MarshalBinary implements encoding.BinaryMarshaler
func (ac *AuthorizationCode) MarshalBinary() ([]byte, error) {
	return json.Marshal(ac)
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler
func (ac *AuthorizationCode) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, ac)
}

type AccessToken struct {
	Token     string    `json:"token"`
	UserID    int       `json:"user_id"`
	ClientID  string    `json:"client_id"`
	Scope     string    `json:"scope"`
	ExpiresAt time.Time `json:"expires_at"`
}

// MarshalBinary implements encoding.BinaryMarshaler for Redis serialization
func (t *AccessToken) MarshalBinary() ([]byte, error) {
	return json.Marshal(t)
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler for Redis deserialization
func (t *AccessToken) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, t)
}

type RefreshToken struct {
	Token     string    `json:"token"`
	UserID    int       `json:"user_id"`
	ClientID  string    `json:"client_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// MarshalBinary implements encoding.BinaryMarshaler for Redis serialization
func (t *RefreshToken) MarshalBinary() ([]byte, error) {
	return json.Marshal(t)
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler for Redis deserialization
func (t *RefreshToken) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, t)
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type ErrorResponse struct {
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

func NewProvider(cfg *config.Config, db *database.PostgreSQL, redis *redis.Client, logger *logger.Logger) *Provider {
	return &Provider{
		cfg:    cfg,
		db:     db,
		redis:  redis,
		logger: logger,
	}
}

// GenerateAuthorizationCode creates a new authorization code
func (p *Provider) GenerateAuthorizationCode(ctx context.Context, clientID string, userID int, redirectURI, scope, challenge, method string) (*AuthorizationCode, error) {
	code := generateSecureToken(32)
	authCode := &AuthorizationCode{
		Code:        code,
		ClientID:    clientID,
		UserID:      userID,
		RedirectURI: redirectURI,
		Scope:       scope,
		ExpiresAt:   time.Now().Add(10 * time.Minute), // Authorization codes expire in 10 minutes
		Challenge:   challenge,
		Method:      method,
	}

	// Store in Redis with expiration
	key := fmt.Sprintf("auth_code:%s", code)
	err := p.redis.Set(ctx, key, authCode, 10*time.Minute).Err()
	if err != nil {
		return nil, fmt.Errorf("failed to store authorization code: %w", err)
	}

	p.logger.OAuthLog("authorization_code_generated", clientID, userID, map[string]interface{}{
		"code":         code,
		"redirect_uri": redirectURI,
		"scope":        scope,
		"expires_at":   authCode.ExpiresAt,
	})

	return authCode, nil
}

// ExchangeAuthorizationCode exchanges authorization code for access token
func (p *Provider) ExchangeAuthorizationCode(ctx context.Context, code, clientID, clientSecret, redirectURI, codeVerifier string) (*TokenResponse, error) {
	// Retrieve authorization code from Redis
	key := fmt.Sprintf("auth_code:%s", code)
	var authCode AuthorizationCode
	err := p.redis.Get(ctx, key).Scan(&authCode)
	if err != nil {
		if err == redis.Nil {
			return nil, &ErrorResponse{
				ErrorCode:        "invalid_grant",
				ErrorDescription: "Authorization code not found or expired",
			}
		}
		return nil, fmt.Errorf("failed to retrieve authorization code: %w", err)
	}

	// Validate authorization code
	if authCode.ClientID != clientID {
		return nil, &ErrorResponse{
			ErrorCode:        "invalid_grant",
			ErrorDescription: "Client ID mismatch",
		}
	}

	if authCode.RedirectURI != redirectURI {
		return nil, &ErrorResponse{
			ErrorCode:        "invalid_grant",
			ErrorDescription: "Redirect URI mismatch",
		}
	}

	if time.Now().After(authCode.ExpiresAt) {
		p.redis.Del(ctx, key) // Clean up expired code
		return nil, &ErrorResponse{
			ErrorCode:        "invalid_grant",
			ErrorDescription: "Authorization code expired",
		}
	}

	// Validate client credentials (conditional for public clients with PKCE)
	client := p.cfg.GetOAuthClient(clientID)
	if client == nil {
		return nil, &ErrorResponse{
			ErrorCode:        "invalid_client",
			ErrorDescription: "Invalid client",
		}
	}

	// For public clients with PKCE, skip client_secret validation
	requiresSecret := client.ClientType != "public" || authCode.Challenge == ""
	if requiresSecret && client.ClientSecret != clientSecret {
		return nil, &ErrorResponse{
			ErrorCode:        "invalid_client",
			ErrorDescription: "Invalid client credentials",
		}
	}

	// Validate PKCE if used
	if authCode.Challenge != "" {
		if codeVerifier == "" {
			return nil, &ErrorResponse{
				ErrorCode:        "invalid_request",
				ErrorDescription: "Code verifier required for PKCE",
			}
		}

		if !p.validatePKCE(authCode.Challenge, codeVerifier, authCode.Method) {
			return nil, &ErrorResponse{
				ErrorCode:        "invalid_grant",
				ErrorDescription: "PKCE verification failed",
			}
		}
	}

	// Generate tokens
	accessToken := generateSecureToken(32)
	refreshToken := generateSecureToken(32)

	// Store access token
	accessTokenKey := fmt.Sprintf("access_token:%s", accessToken)
	accessTokenData := &AccessToken{
		Token:     accessToken,
		UserID:    authCode.UserID,
		ClientID:  clientID,
		Scope:     authCode.Scope,
		ExpiresAt: time.Now().Add(p.cfg.JWT.AccessTokenDuration),
	}
	err = p.redis.Set(ctx, accessTokenKey, accessTokenData, p.cfg.JWT.AccessTokenDuration).Err()
	if err != nil {
		return nil, fmt.Errorf("failed to store access token: %w", err)
	}

	// Store refresh token
	refreshTokenKey := fmt.Sprintf("refresh_token:%s", refreshToken)
	refreshTokenData := &RefreshToken{
		Token:     refreshToken,
		UserID:    authCode.UserID,
		ClientID:  clientID,
		ExpiresAt: time.Now().Add(p.cfg.JWT.RefreshTokenDuration),
	}
	err = p.redis.Set(ctx, refreshTokenKey, refreshTokenData, p.cfg.JWT.RefreshTokenDuration).Err()
	if err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	// Delete used authorization code
	p.redis.Del(ctx, key)

	p.logger.OAuthLog("token_exchange", clientID, authCode.UserID, map[string]interface{}{
		"access_token_expires_at":  accessTokenData.ExpiresAt,
		"refresh_token_expires_at": refreshTokenData.ExpiresAt,
		"scope":                    authCode.Scope,
	})

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(p.cfg.JWT.AccessTokenDuration.Seconds()),
		RefreshToken: refreshToken,
		Scope:        authCode.Scope,
	}, nil
}

// RefreshAccessToken generates new access token using refresh token
func (p *Provider) RefreshAccessToken(ctx context.Context, refreshToken, clientID, clientSecret string) (*TokenResponse, error) {
	// Validate client credentials (conditional for public clients)
	client := p.cfg.GetOAuthClient(clientID)
	if client == nil {
		return nil, &ErrorResponse{
			ErrorCode:        "invalid_client",
			ErrorDescription: "Invalid client",
		}
	}

	// For public clients, skip client_secret validation
	if client.ClientType != "public" && client.ClientSecret != clientSecret {
		return nil, &ErrorResponse{
			ErrorCode:        "invalid_client",
			ErrorDescription: "Invalid client credentials",
		}
	}

	// Retrieve refresh token from Redis
	key := fmt.Sprintf("refresh_token:%s", refreshToken)
	var tokenData RefreshToken
	err := p.redis.Get(ctx, key).Scan(&tokenData)
	if err != nil {
		if err == redis.Nil {
			return nil, &ErrorResponse{
				ErrorCode:        "invalid_grant",
				ErrorDescription: "Refresh token not found or expired",
			}
		}
		return nil, fmt.Errorf("failed to retrieve refresh token: %w", err)
	}

	// Validate refresh token
	if tokenData.ClientID != clientID {
		return nil, &ErrorResponse{
			ErrorCode:        "invalid_grant",
			ErrorDescription: "Client ID mismatch",
		}
	}

	if time.Now().After(tokenData.ExpiresAt) {
		p.redis.Del(ctx, key) // Clean up expired token
		return nil, &ErrorResponse{
			ErrorCode:        "invalid_grant",
			ErrorDescription: "Refresh token expired",
		}
	}

	// Generate new access token
	newAccessToken := generateSecureToken(32)
	newAccessTokenData := &AccessToken{
		Token:     newAccessToken,
		UserID:    tokenData.UserID,
		ClientID:  clientID,
		Scope:     "read write", // Default scope for refresh
		ExpiresAt: time.Now().Add(p.cfg.JWT.AccessTokenDuration),
	}

	// Store new access token
	accessTokenKey := fmt.Sprintf("access_token:%s", newAccessToken)
	err = p.redis.Set(ctx, accessTokenKey, newAccessTokenData, p.cfg.JWT.AccessTokenDuration).Err()
	if err != nil {
		return nil, fmt.Errorf("failed to store new access token: %w", err)
	}

	p.logger.OAuthLog("token_refresh", clientID, tokenData.UserID, map[string]interface{}{
		"access_token_expires_at": newAccessTokenData.ExpiresAt,
	})

	return &TokenResponse{
		AccessToken: newAccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(p.cfg.JWT.AccessTokenDuration.Seconds()),
		Scope:       newAccessTokenData.Scope,
	}, nil
}

// ValidateAccessToken validates and returns access token information
func (p *Provider) ValidateAccessToken(ctx context.Context, token string) (*AccessToken, error) {
	key := fmt.Sprintf("access_token:%s", token)
	var tokenData AccessToken
	err := p.redis.Get(ctx, key).Scan(&tokenData)
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("access token not found")
		}
		return nil, fmt.Errorf("failed to retrieve access token: %w", err)
	}

	if time.Now().After(tokenData.ExpiresAt) {
		p.redis.Del(ctx, key) // Clean up expired token
		return nil, fmt.Errorf("access token expired")
	}

	return &tokenData, nil
}

// GenerateJWT creates a JWT token for the user (alternative to opaque tokens)
func (p *Provider) GenerateJWT(ctx context.Context, userID int, clientID string, scope string) (string, error) {
	claims := jwt.MapClaims{
		"sub":       fmt.Sprintf("%d", userID),
		"client_id": clientID,
		"scope":     scope,
		"iss":       p.cfg.OAuth.Issuer,
		"aud":       clientID,
		"exp":       time.Now().Add(p.cfg.JWT.AccessTokenDuration).Unix(),
		"iat":       time.Now().Unix(),
		"jti":       uuid.New().String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(p.cfg.JWT.Secret))
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return tokenString, nil
}

// ValidateJWT validates and parses JWT token
func (p *Provider) ValidateJWT(tokenString string) (*jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(p.cfg.JWT.Secret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return &claims, nil
	}

	return nil, fmt.Errorf("invalid JWT token")
}

// validatePKCE validates PKCE code challenge
func (p *Provider) validatePKCE(challenge, verifier, method string) bool {
	if method == "" || method == "plain" {
		return challenge == verifier
	}

	if method == "S256" {
		// SHA256 and base64url encode
		hash := generateCodeChallenge(verifier)
		return challenge == hash
	}

	return false
}

// generateSecureToken generates a cryptographically secure random token
func generateSecureToken(length int) string {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(fmt.Sprintf("failed to generate secure token: %v", err))
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length]
}

// generateCodeChallenge generates PKCE code challenge from verifier
func generateCodeChallenge(verifier string) string {
	// Proper SHA256 + base64url encoding as per RFC 7636
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// isValidRedirectURI checks if the redirect URI is valid for the client
func isValidRedirectURI(client *config.OAuthClientConfig, redirectURI string) bool {
	if client == nil {
		return false
	}
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			return true
		}
	}
	return false
}

// BuildAuthorizationURL builds the OAuth authorization URL
func (p *Provider) BuildAuthorizationURL(clientID, redirectURI, scope, state string, usePKCE bool) (string, string, error) {
	client := p.cfg.GetOAuthClient(clientID)
	if client == nil {
		return "", "", fmt.Errorf("client not found")
	}

	if !isValidRedirectURI(client, redirectURI) {
		return "", "", fmt.Errorf("invalid redirect URI")
	}

	params := url.Values{}
	params.Add("response_type", "code")
	params.Add("client_id", clientID)
	params.Add("redirect_uri", redirectURI)
	params.Add("scope", scope)
	params.Add("state", state)

	var codeVerifier string
	if usePKCE {
		codeVerifier = generateSecureToken(43) // PKCE verifier
		challenge := generateCodeChallenge(codeVerifier)
		params.Add("code_challenge", challenge)
		params.Add("code_challenge_method", "S256")
	}

	authURL := fmt.Sprintf("%s/oauth/authorize?%s", p.cfg.OAuth.Issuer, params.Encode())
	return authURL, codeVerifier, nil
}

// Error implements error interface for ErrorResponse
func (e *ErrorResponse) Error() string {
	if e.ErrorDescription != "" {
		return fmt.Sprintf("%s: %s", e.ErrorCode, e.ErrorDescription)
	}
	return e.ErrorCode
}

// HTTPStatusCode returns appropriate HTTP status code for OAuth errors
func (e *ErrorResponse) HTTPStatusCode() int {
	switch e.ErrorCode {
	case "invalid_request":
		return http.StatusBadRequest
	case "invalid_client":
		return http.StatusUnauthorized
	case "invalid_grant", "unauthorized_client":
		return http.StatusBadRequest
	case "unsupported_grant_type":
		return http.StatusBadRequest
	case "invalid_scope":
		return http.StatusBadRequest
	case "server_error":
		return http.StatusInternalServerError
	case "temporarily_unavailable":
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadRequest
	}
}
