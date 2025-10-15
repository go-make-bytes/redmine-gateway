package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/go-make-bytes/redmine-gateway/internal/config"
	"github.com/go-make-bytes/redmine-gateway/internal/database"
	"github.com/go-make-bytes/redmine-gateway/internal/logger"
	"github.com/go-make-bytes/redmine-gateway/internal/oauth"
)

type Handler struct {
	cfg    *config.Config
	db     *database.PostgreSQL
	oauth  *oauth.Provider
	logger *logger.Logger
	redis  *redis.Client
}

type LoginRequest struct {
	Username string `json:"username" form:"username" binding:"required"`
	Password string `json:"password" form:"password" binding:"required"`
}

type AuthorizeRequest struct {
	ResponseType    string `form:"response_type" binding:"required"`
	ClientID        string `form:"client_id" binding:"required"`
	RedirectURI     string `form:"redirect_uri" binding:"required"`
	Scope           string `form:"scope"`
	State           string `form:"state"`
	CodeChallenge   string `form:"code_challenge"`
	ChallengeMethod string `form:"code_challenge_method"`
}

type TokenRequest struct {
	GrantType    string  `form:"grant_type" binding:"required"`
	Code         string  `form:"code"`
	RedirectURI  string  `form:"redirect_uri"`
	ClientID     string  `form:"client_id" binding:"required"`
	ClientSecret *string `form:"client_secret"` // Optional pointer
	RefreshToken string  `form:"refresh_token"`
	CodeVerifier string  `form:"code_verifier"`
}

func NewHandler(cfg *config.Config, db *database.PostgreSQL, oauth *oauth.Provider, logger *logger.Logger, redis *redis.Client) *Handler {
	return &Handler{
		cfg:    cfg,
		db:     db,
		oauth:  oauth,
		logger: logger,
		redis:  redis,
	}
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

// ShowLogin displays the OAuth login form
func (h *Handler) ShowLogin(c *gin.Context) {
	// Extract OAuth parameters from query string
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	scope := c.Query("scope")
	state := c.Query("state")
	responseType := c.Query("response_type")
	codeChallenge := c.Query("code_challenge")
	challengeMethod := c.Query("code_challenge_method")

	// Validate basic OAuth parameters
	if clientID == "" || redirectURI == "" || responseType != "code" {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error":             "invalid_request",
			"error_description": "Missing or invalid OAuth parameters",
		})
		return
	}

	// Verify client exists and redirect URI is valid
	client := h.cfg.GetOAuthClient(clientID)
	if client == nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error":             "invalid_client",
			"error_description": "Unknown OAuth client",
		})
		return
	}

	if !isValidRedirectURI(client, redirectURI) {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid redirect URI",
		})
		return
	}

	// Display login form with OAuth parameters preserved
	c.HTML(http.StatusOK, "login.html", gin.H{
		"client_id":             clientID,
		"client_name":           client.Name,
		"redirect_uri":          redirectURI,
		"scope":                 scope,
		"state":                 state,
		"response_type":         responseType,
		"code_challenge":        codeChallenge,
		"code_challenge_method": challengeMethod,
	})
}

// ProcessLogin handles the login form submission
func (h *Handler) ProcessLogin(c *gin.Context) {
	ctx := context.Background()

	// Extract credentials directly from form
	username := c.PostForm("username")
	password := c.PostForm("password")

	if username == "" || password == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Username and password are required",
		})
		return
	}

	// Extract OAuth parameters
	clientID := c.PostForm("client_id")
	redirectURI := c.PostForm("redirect_uri")
	scope := c.PostForm("scope")
	state := c.PostForm("state")
	codeChallenge := c.PostForm("code_challenge")
	challengeMethod := c.PostForm("code_challenge_method")

	// Debug logging for state parameter
	h.logger.Logger.WithFields(map[string]interface{}{
		"state":        state,
		"state_length": len(state),
		"state_bytes":  []byte(state),
	}).Debug("OAuth service received state parameter")

	h.logger.SecurityLog("login_attempt", 0, c.ClientIP(), map[string]interface{}{
		"username":  username,
		"client_id": clientID,
	})

	// Authenticate user against PostgreSQL
	user, err := h.db.AuthenticateUser(ctx, username, password)
	if err != nil {
		h.logger.SecurityLog("login_failed", 0, c.ClientIP(), map[string]interface{}{
			"username": username,
			"error":    err.Error(),
		})

		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"client_id":             clientID,
			"redirect_uri":          redirectURI,
			"scope":                 scope,
			"state":                 state,
			"code_challenge":        codeChallenge,
			"code_challenge_method": challengeMethod,
			"error":                 "Invalid username or password",
		})
		return
	}

	h.logger.SecurityLog("login_success", user.ID, c.ClientIP(), map[string]interface{}{
		"username":  user.Login,
		"client_id": clientID,
	})

	// Generate authorization code
	authCode, err := h.oauth.GenerateAuthorizationCode(ctx, clientID, user.ID, redirectURI, scope, codeChallenge, challengeMethod)
	if err != nil {
		h.logger.Logger.WithField("error", err.Error()).Error("Failed to generate authorization code")
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error":             "server_error",
			"error_description": "Failed to generate authorization code",
		})
		return
	}

	// Redirect back to client with authorization code
	redirectURL := redirectURI + "?code=" + authCode.Code
	if state != "" {
		redirectURL += "&state=" + state
		h.logger.Logger.WithFields(map[string]interface{}{
			"state":        state,
			"state_length": len(state),
			"redirect_url": redirectURL,
		}).Debug("Redirecting with state parameter")
	}

	c.Redirect(http.StatusFound, redirectURL)
}

// HandleAuthorize handles OAuth authorization endpoint with session-based security
func (h *Handler) HandleAuthorize(c *gin.Context) {
	ctx := context.Background()

	var req AuthorizeRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid authorization request parameters",
		})
		return
	}

	// Validate OAuth parameters
	client := h.cfg.GetOAuthClient(req.ClientID)
	if client == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_client",
			"error_description": "Unknown OAuth client",
		})
		return
	}

	if !isValidRedirectURI(client, req.RedirectURI) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid redirect URI",
		})
		return
	}

	if req.ResponseType != "code" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_response_type",
			"error_description": "Only 'code' response type is supported",
		})
		return
	}

	// Check for existing authentication session
	sessionToken, err := c.Cookie("auth_session")
	if err != nil {
		// No session - redirect to secure authentication
		authURL := fmt.Sprintf("/auth/login?return_to=%s",
			url.QueryEscape(c.Request.URL.String()))
		c.Redirect(http.StatusFound, authURL)
		return
	}

	// Validate session using session manager if available
	// For now, we'll implement basic Redis validation
	sessionKey := fmt.Sprintf("auth_session:%s", sessionToken)
	sessionDataStr, err := h.redis.Get(ctx, sessionKey).Result()
	if err != nil {
		// Invalid session - redirect to authentication
		authURL := fmt.Sprintf("/auth/login?return_to=%s",
			url.QueryEscape(c.Request.URL.String()))
		c.Redirect(http.StatusFound, authURL)
		return
	}

	// Parse session data to get user ID
	var sessionData map[string]interface{}
	if err := json.Unmarshal([]byte(sessionDataStr), &sessionData); err != nil {
		h.logger.Logger.WithField("error", err.Error()).Error("Failed to parse session data")
		authURL := fmt.Sprintf("/auth/login?return_to=%s",
			url.QueryEscape(c.Request.URL.String()))
		c.Redirect(http.StatusFound, authURL)
		return
	}

	userID := int(sessionData["user_id"].(float64))

	// Generate authorization code
	authCode, err := h.oauth.GenerateAuthorizationCode(
		ctx, req.ClientID, userID, req.RedirectURI,
		req.Scope, req.CodeChallenge, req.ChallengeMethod)
	if err != nil {
		h.logger.Logger.WithField("error", err.Error()).Error("Failed to generate authorization code")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to generate authorization code",
		})
		return
	}

	// Clean up session after successful authorization
	h.redis.Del(ctx, sessionKey)
	c.SetCookie("auth_session", "", -1, "/", "", true, true)

	// Redirect with authorization code
	redirectURL := fmt.Sprintf("%s?code=%s", req.RedirectURI, authCode.Code)
	if req.State != "" {
		redirectURL += "&state=" + req.State
	}

	h.logger.OAuthLog("authorization_code_issued", req.ClientID, userID, map[string]interface{}{
		"code":         authCode.Code,
		"redirect_uri": req.RedirectURI,
		"scope":        req.Scope,
	})

	c.Redirect(http.StatusFound, redirectURL)
}

// HandleToken handles OAuth token endpoint
func (h *Handler) HandleToken(c *gin.Context) {
	ctx := context.Background()

	// Debug: Log the incoming request
	h.logger.Logger.WithFields(map[string]interface{}{
		"method":       c.Request.Method,
		"content_type": c.GetHeader("Content-Type"),
		"body_size":    c.Request.ContentLength,
	}).Info("Token request received")

	var req TokenRequest
	if err := c.ShouldBind(&req); err != nil {
		h.logger.Logger.WithFields(map[string]interface{}{
			"error":        err.Error(),
			"content_type": c.GetHeader("Content-Type"),
		}).Error("Failed to bind token request")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid token request format: " + err.Error(),
		})
		return
	}

	// Debug: Log the parsed request
	h.logger.Logger.WithFields(map[string]interface{}{
		"grant_type":   req.GrantType,
		"client_id":    req.ClientID,
		"code_present": req.Code != "",
		"redirect_uri": req.RedirectURI,
	}).Info("Token request parsed successfully")

	switch req.GrantType {
	case "authorization_code":
		h.handleAuthorizationCodeGrant(ctx, c, &req)
	case "refresh_token":
		h.handleRefreshTokenGrant(ctx, c, &req)
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "Grant type not supported",
		})
	}
}

func (h *Handler) handleAuthorizationCodeGrant(ctx context.Context, c *gin.Context, req *TokenRequest) {
	if req.Code == "" || req.RedirectURI == "" {
		h.logger.Logger.WithFields(map[string]interface{}{
			"code_present":         req.Code != "",
			"redirect_uri_present": req.RedirectURI != "",
		}).Error("Missing required parameters for token exchange")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Missing required parameters",
		})
		return
	}

	h.logger.Logger.WithFields(map[string]interface{}{
		"code":         req.Code,
		"client_id":    req.ClientID,
		"redirect_uri": req.RedirectURI,
	}).Info("Attempting token exchange")

	clientSecret := ""
	if req.ClientSecret != nil {
		clientSecret = *req.ClientSecret
	}

	tokenResp, err := h.oauth.ExchangeAuthorizationCode(ctx, req.Code, req.ClientID, clientSecret, req.RedirectURI, req.CodeVerifier)
	if err != nil {
		if oauthErr, ok := err.(*oauth.ErrorResponse); ok {
			h.logger.Logger.WithFields(map[string]interface{}{
				"error":       oauthErr.ErrorCode,
				"description": oauthErr.ErrorDescription,
				"code":        req.Code,
			}).Error("OAuth token exchange failed")
			c.JSON(oauthErr.HTTPStatusCode(), oauthErr)
			return
		}

		h.logger.Logger.WithFields(map[string]interface{}{
			"error": err.Error(),
			"code":  req.Code,
		}).Error("Token exchange failed")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Internal server error",
		})
		return
	}

	h.logger.Logger.WithFields(map[string]interface{}{
		"code":      req.Code,
		"client_id": req.ClientID,
	}).Info("Token exchange successful")

	c.JSON(http.StatusOK, tokenResp)
}

func (h *Handler) handleRefreshTokenGrant(ctx context.Context, c *gin.Context, req *TokenRequest) {
	if req.RefreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Missing refresh token",
		})
		return
	}

	clientSecret := ""
	if req.ClientSecret != nil {
		clientSecret = *req.ClientSecret
	}

	tokenResp, err := h.oauth.RefreshAccessToken(ctx, req.RefreshToken, req.ClientID, clientSecret)
	if err != nil {
		if oauthErr, ok := err.(*oauth.ErrorResponse); ok {
			c.JSON(oauthErr.HTTPStatusCode(), oauthErr)
			return
		}

		h.logger.Logger.WithField("error", err.Error()).Error("Token refresh failed")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Internal server error",
		})
		return
	}

	c.JSON(http.StatusOK, tokenResp)
}

// HandleUserInfo returns user information for valid access token
func (h *Handler) HandleUserInfo(c *gin.Context) {
	ctx := context.Background()

	// Extract access token from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_request",
			"error_description": "Missing Authorization header",
		})
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == authHeader {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid Authorization header format",
		})
		return
	}

	// Validate access token
	accessToken, err := h.oauth.ValidateAccessToken(ctx, token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_token",
			"error_description": "Access token is invalid or expired",
		})
		return
	}

	// Get user information
	user, err := h.db.GetUserByID(ctx, accessToken.UserID)
	if err != nil {
		h.logger.Logger.WithField("error", err.Error()).Error("Failed to get user info")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to retrieve user information",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"sub":        strconv.Itoa(user.ID),
		"login":      user.Login,
		"firstname":  user.Firstname,
		"lastname":   user.Lastname,
		"email":      user.Mail,
		"status":     user.Status,
		"created_on": user.CreatedOn,
		"updated_on": user.UpdatedOn,
	})
}

// Middleware to authenticate API requests using access tokens
func (h *Handler) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := context.Background()

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Missing Authorization header",
			})
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == authHeader {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid Authorization header format",
			})
			return
		}

		accessToken, err := h.oauth.ValidateAccessToken(ctx, token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired access token",
			})
			return
		}

		// Set user context for downstream handlers
		c.Set("user_id", accessToken.UserID)
		c.Set("client_id", accessToken.ClientID)
		c.Set("scope", accessToken.Scope)

		c.Next()
	}
}

// Health check endpoint
func (h *Handler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now(),
		"service":   "oauth-provider",
	})
}
