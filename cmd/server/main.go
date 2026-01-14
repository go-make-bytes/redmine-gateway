package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/go-make-bytes/redmine-gateway/internal/config"
	"github.com/go-make-bytes/redmine-gateway/internal/database"
	"github.com/go-make-bytes/redmine-gateway/internal/handlers"
	"github.com/go-make-bytes/redmine-gateway/internal/logger"
	"github.com/go-make-bytes/redmine-gateway/internal/middleware"
	"github.com/go-make-bytes/redmine-gateway/internal/oauth"
	"github.com/go-make-bytes/redmine-gateway/internal/redmine"
	"github.com/go-make-bytes/redmine-gateway/internal/session"
	"github.com/go-make-bytes/redmine-gateway/internal/twofa"
)

func main() {
	// Load configuration first for logging
	cfg, err := config.Load()
	if err != nil {
		// Can't use logger yet, use fmt
		fmt.Printf("Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger with config
	log := logger.New(cfg.LogLevel, cfg.LogFormat)
	log.Logger.Info("Starting OAuth service...")

	// Debug: Log CORS configuration
	log.Logger.WithField("cors_origins", cfg.Security.CORSOrigins).Info("Loaded CORS configuration")

	// Initialize PostgreSQL connection
	db, err := database.NewPostgreSQL(cfg.Database.ConnectionString)
	if err != nil {
		log.Logger.WithField("error", err.Error()).Error("Failed to connect to PostgreSQL")
		os.Exit(1)
	}
	defer db.Close()

	// Detect platform (OSS Redmine vs EasyRedmine)
	platformCtx, platformCancel := context.WithTimeout(context.Background(), 5*time.Second)
	platformInfo, err := db.DetectPlatform(platformCtx, &cfg.Platform)
	platformCancel()
	if err != nil {
		log.Logger.WithField("error", err.Error()).Error("Failed to detect platform")
		os.Exit(1)
	}
	db.SetPlatformInfo(platformInfo)

	log.Logger.WithFields(map[string]interface{}{
		"platform":         string(platformInfo.Platform),
		"version":          platformInfo.Version,
		"has_2fa_table":    platformInfo.Has2FATable,
		"has_user_types":   platformInfo.HasUserTypes,
		"has_easy_modules": platformInfo.HasEasyModules,
	}).Info("Platform detected")

	// Initialize Redis client with TLS support if configured
	redisOptions := &redis.Options{
		Addr:     cfg.Redis.Address,
		Username: cfg.Redis.Username,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	}

	// Enable TLS if configured
	if cfg.Redis.UseTLS {
		redisOptions.TLSConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: cfg.Redis.TLSSkipVerify,
		}
		if cfg.Redis.TLSSkipVerify {
			log.Logger.Warn("Redis TLS certificate verification disabled (insecure)")
		}
		log.Logger.Info("Redis TLS enabled for production connection")
	}

	redisClient := redis.NewClient(redisOptions)
	defer redisClient.Close()

	// Test Redis connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.Logger.WithField("error", err.Error()).Error("Failed to connect to Redis")
		os.Exit(1)
	}

	// Get Redis prefix from config (defaults to empty string for backward compatibility)
	redisPrefix := cfg.Redis.Prefix
	if redisPrefix != "" && !strings.HasSuffix(redisPrefix, ":") {
		redisPrefix = redisPrefix + ":" // Ensure prefix ends with colon
	}

	// Initialize OAuth provider with Redis prefix
	oauthProvider := oauth.NewProvider(cfg, db, redisClient, log, redisPrefix)

	// Initialize security components
	sessionManager := session.NewSessionManager(redisClient, log, cfg.Security.SessionTimeout, redisPrefix)
	inputValidator := middleware.NewInputValidator(cfg.Security.MaxUsernameLen, cfg.Security.MaxPasswordLen)
	csrfProtection := middleware.NewCSRFProtection(redisClient, log, cfg.Security.CSRFSecret, redisPrefix)
	securityMiddleware := middleware.NewSecurityMiddleware(redisClient, log, redisPrefix)

	// Initialize 2FA components
	twofaSessionManager := session.NewTwoFASessionManager(redisClient, log, cfg, redisPrefix)
	totpService := twofa.NewTOTPService(cfg)

	// Initialize handlers
	oauthHandler := handlers.NewHandler(cfg, db, oauthProvider, log, redisClient, sessionManager)
	redmineHandler := redmine.NewRedmineHandler(cfg, db, log)
	authHandler := handlers.NewAuthHandler(cfg, db, log, sessionManager, twofaSessionManager, inputValidator, csrfProtection, redisClient)
	twofaHandler := handlers.NewTwoFAHandler(db, twofaSessionManager, sessionManager, totpService, oauthProvider, log, cfg)

	// Debug: Check if handlers are initialized
	if oauthHandler == nil {
		log.Logger.Error("Failed to initialize OAuth handler")
		os.Exit(1)
	}
	if redmineHandler == nil {
		log.Logger.Error("Failed to initialize Redmine handler")
		os.Exit(1)
	}
	log.Logger.Info("All handlers initialized successfully")

	// Setup Gin router
	if cfg.Server.Mode == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// Custom logging middleware that skips health checks
	router.Use(gin.LoggerWithConfig(gin.LoggerConfig{
		SkipPaths: []string{"/health"},
	}))

	router.Use(gin.Recovery())

	// Security middleware
	router.Use(securityMiddleware.SecurityHeaders())
	router.Use(securityMiddleware.RateLimiter(cfg.Security.RateLimit.LoginAttempts, int(cfg.Security.RateLimit.LoginWindow.Minutes())))

	// CORS middleware
	router.Use(middleware.CORSMiddleware(cfg.Security.CORSOrigins))

	// Load HTML templates
	router.LoadHTMLGlob("templates/*")

	// Get base path from config (e.g., "/gateway" for reverse proxy routing)
	basePath := cfg.Server.BasePath
	if basePath != "" && !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}

	// Secure Authentication endpoints (NEW)
	authGroup := router.Group(basePath + "/auth")
	authGroup.Use(securityMiddleware.TwoFARateLimiter(5, 15)) // 5 attempts per 15 minutes for 2FA
	authGroup.Use(securityMiddleware.TwoFASecurityHeaders())  // Enhanced security headers for 2FA
	{
		authGroup.GET("/login", authHandler.ShowLoginPage)
		authGroup.POST("/login", authHandler.Login)
		authGroup.POST("/logout", authHandler.Logout)
		authGroup.GET("/session", authHandler.CheckSession)

		// Password change endpoints
		authGroup.GET("/password/change", authHandler.ShowPasswordChangePage)
		authGroup.POST("/password/change", authHandler.ChangePassword)

		// Two-Factor Authentication endpoints
		authGroup.GET("/2fa/verify", twofaHandler.ShowTwoFAVerifyPage)
		authGroup.POST("/2fa/verify", twofaHandler.TwoFAVerify)
		authGroup.GET("/2fa/setup", twofaHandler.TwoFASetup)           // Returns JSON data for enrollment
		authGroup.GET("/2fa/enroll", twofaHandler.ShowTwoFAEnrollPage) // Shows HTML page
		authGroup.POST("/2fa/setup", twofaHandler.TwoFASetup)
		authGroup.POST("/2fa/confirm", twofaHandler.TwoFAConfirm)

		// Protected 2FA management endpoints (require authenticated session)
		authGroup.Use(authHandler.SessionAuthMiddleware())
		{
			authGroup.POST("/2fa/disable", twofaHandler.TwoFADisable)
			authGroup.GET("/2fa/status", twofaHandler.TwoFAStatus)
			authGroup.POST("/2fa/backup-codes", twofaHandler.BackupCodesGenerate)
		}
	}

	// OAuth endpoints (UPDATED)
	oauthGroup := router.Group(basePath + "/oauth")
	{
		oauthGroup.GET("/authorize", oauthHandler.HandleAuthorize)
		oauthGroup.POST("/token", oauthHandler.HandleToken)
		oauthGroup.GET("/userinfo", oauthHandler.HandleUserInfo)
	}

	// Protected API endpoints (require valid access token)
	api := router.Group(basePath + "/api")
	api.Use(oauthHandler.AuthMiddleware())
	{
		// User information - special endpoint, not proxied
		api.GET("/user", redmineHandler.GetCurrentUser)

		// Specific Redmine API endpoints
		api.GET("/projects", redmineHandler.ProxyRedmineAPI)
		api.POST("/projects", redmineHandler.ProxyRedmineAPI)
		// More specific routes must come before general :id routes
		api.GET("/projects/:id/memberships", redmineHandler.ProxyRedmineAPI)
		api.GET("/projects/:id/assignable_users", redmineHandler.GetAssignableUsers)
		api.GET("/projects/:id", redmineHandler.ProxyRedmineAPI)
		api.PUT("/projects/:id", redmineHandler.ProxyRedmineAPI)
		api.DELETE("/projects/:id", redmineHandler.ProxyRedmineAPI)

		api.GET("/issues", redmineHandler.ProxyRedmineAPI)
		api.POST("/issues", redmineHandler.ProxyRedmineAPI)
		// Allowed statuses endpoint - queries DB directly for workflow-based status transitions
		api.GET("/issues/allowed_statuses", redmineHandler.GetAllowedStatusesForIssue)
		api.GET("/issues/:id", redmineHandler.ProxyRedmineAPI)
		api.PUT("/issues/:id", redmineHandler.ProxyRedmineAPI)
		api.DELETE("/issues/:id", redmineHandler.ProxyRedmineAPI)

		api.GET("/users", redmineHandler.ProxyRedmineAPI)
		api.GET("/users/current", redmineHandler.ProxyRedmineAPI)
		api.GET("/users/:id", redmineHandler.ProxyRedmineAPI)

		// Enhanced time entries endpoint with issue subjects
		api.GET("/time_entries/enriched", redmineHandler.GetEnrichedTimeEntries)

		// Task Involvement Report endpoint
		api.GET("/reports/task-involvement", redmineHandler.GetTaskInvolvement)

		// Standard time entries endpoints (fallback to proxy)
		api.GET("/time_entries", redmineHandler.ProxyRedmineAPI)
		api.POST("/time_entries", redmineHandler.CreateTimeEntry)
		api.GET("/time_entries/:id", redmineHandler.ProxyRedmineAPI)
		api.PUT("/time_entries/:id", redmineHandler.ProxyRedmineAPI)
		api.DELETE("/time_entries/:id", redmineHandler.ProxyRedmineAPI)

		api.POST("/uploads", redmineHandler.ProxyRedmineAPI)
		api.GET("/attachments/:id", redmineHandler.ProxyRedmineAPI)

		api.GET("/trackers", redmineHandler.ProxyRedmineAPI)
		api.GET("/issue_statuses", redmineHandler.ProxyRedmineAPI)
		api.GET("/issue_priorities", redmineHandler.ProxyRedmineAPI)
		api.GET("/enumerations", redmineHandler.ProxyRedmineAPI)
		api.GET("/enumerations/issue_priorities", redmineHandler.ProxyRedmineAPI)
		api.GET("/custom_fields", redmineHandler.ProxyRedmineAPI)
	}

	// Health and status endpoints
	router.GET(basePath+"/health", oauthHandler.Health)
	router.GET(basePath+"/redmine/status", redmineHandler.ValidateRedmineConnection)

	// Debug: Log router setup complete
	log.Logger.Info("Router setup complete with all handlers")

	// Start server
	server := &http.Server{
		Addr:    ":" + cfg.Server.Port,
		Handler: router,
	}

	// Graceful shutdown
	go func() {
		log.Logger.WithField("port", cfg.Server.Port).Info("Server starting")
		log.Logger.WithFields(map[string]interface{}{
			"authorize": fmt.Sprintf("http://localhost:%s%s/oauth/authorize", cfg.Server.Port, basePath),
			"token":     fmt.Sprintf("http://localhost:%s%s/oauth/token", cfg.Server.Port, basePath),
			"userinfo":  fmt.Sprintf("http://localhost:%s%s/oauth/userinfo", cfg.Server.Port, basePath),
		}).Info("OAuth endpoints")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Logger.WithField("error", err.Error()).Error("Server failed to start")
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Logger.Info("Shutting down server...")

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Logger.WithField("error", err.Error()).Error("Server forced to shutdown")
		os.Exit(1)
	}

	log.Logger.Info("Server exited")
}
