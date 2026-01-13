package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type RedmineConfig struct {
	BaseURL       string        `yaml:"base_url"`
	Timeout       time.Duration `yaml:"timeout"`
	SecretKeyBase string        `yaml:"secret_key_base"` // To encrypt TOTP keys in database, now compatible with redmine native login.
}

type TwoFactorConfig struct {
	Enabled         bool             `yaml:"enabled"`
	SessionTimeout  int              `yaml:"session_timeout"`   // Seconds (5 minutes = 300)
	LockoutDuration int              `yaml:"lockout_duration"`  // Seconds (1 hour = 3600)
	MaxAttempts     int              `yaml:"max_attempts"`      // 3 attempts
	TrustedProxyIPs []string         `yaml:"trusted_proxy_ips"` // For X-Forwarded-For validation
	TOTP            TOTPConfig       `yaml:"totp"`
	BackupCode      BackupCodeConfig `yaml:"backup_code"`
}

type TOTPConfig struct {
	Issuer string `yaml:"issuer"` // Displayed in authenticator apps
	Period int    `yaml:"period"` // Seconds (default 30)
	Digits int    `yaml:"digits"` // Code length (default 6)
}

type BackupCodeConfig struct {
	Length int `yaml:"length"` // Character count (default 8)
	Count  int `yaml:"count"`  // Number of codes (default 10)
}

type LDAPConfig struct {
	ConnectionTimeout time.Duration `yaml:"connection_timeout"` // Default 10s
	RetryAttempts     int           `yaml:"retry_attempts"`     // Default 1 (no retries)
}

type ResponseFilterConfig struct {
	Enabled         bool     `yaml:"enabled"`          // Enable/disable response filtering
	SensitiveFields []string `yaml:"sensitive_fields"` // Fields to remove from user responses
	PrivacyFields   []string `yaml:"privacy_fields"`   // Additional privacy fields to remove
}

type PlatformConfig struct {
	AutoDetect bool   `yaml:"auto_detect"` // Default: true
	ForceMode  string `yaml:"force_mode"`  // "oss", "easy", or "" for auto
}

type Config struct {
	Server         ServerConfig         `yaml:"server"`
	Database       DatabaseConfig       `yaml:"database"`
	Redis          RedisConfig          `yaml:"redis"`
	Token          TokenConfig          `yaml:"token"`
	OAuth          OAuthConfig          `yaml:"oauth"`
	Redmine        RedmineConfig        `yaml:"redmine"`
	Security       SecurityConfig       `yaml:"security"`
	TwoFactor      TwoFactorConfig      `yaml:"two_factor"`
	LDAP           LDAPConfig           `yaml:"ldap"`
	ResponseFilter ResponseFilterConfig `yaml:"response_filter"`
	Platform       PlatformConfig       `yaml:"platform"`
	LogLevel       string               `yaml:"log_level"`
	LogFormat      string               `yaml:"log_format"`
}

type ServerConfig struct {
	Host         string        `yaml:"host"`
	Port         string        `yaml:"port"`
	Mode         string        `yaml:"mode"`
	BaseURL      string        `yaml:"base_url"`
	BasePath     string        `yaml:"base_path"` // API base path prefix (e.g., "/gateway")
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
}

type DatabaseConfig struct {
	ConnectionString string `yaml:"connection_string"`
}

type RedisConfig struct {
	Address       string `yaml:"address"`
	Username      string `yaml:"username"`
	Password      string `yaml:"password"`
	DB            int    `yaml:"db"`
	Prefix        string `yaml:"prefix"`
	UseTLS        bool   `yaml:"use_tls"`         // Enable TLS for production Redis
	TLSSkipVerify bool   `yaml:"tls_skip_verify"` // Skip TLS certificate verification (use for legacy certs)
}

type TokenConfig struct {
	Secret               string        `yaml:"secret"`
	AccessTokenDuration  time.Duration `yaml:"access_token_duration"`
	RefreshTokenDuration time.Duration `yaml:"refresh_token_duration"`
	Issuer               string        `yaml:"issuer"`
}

type OAuthConfig struct {
	Issuer               string              `yaml:"issuer"`
	AuthorizationCodeTTL time.Duration       `yaml:"authorization_code_ttl"`
	Clients              []OAuthClientConfig `yaml:"clients"`
}

type OAuthClientConfig struct {
	ClientID     string   `yaml:"client_id"`
	Name         string   `yaml:"name"`
	ClientSecret string   `yaml:"client_secret"`
	ClientType   string   `yaml:"client_type"` // "confidential" or "public"
	RedirectURIs []string `yaml:"redirect_uris"`
	Scopes       []string `yaml:"scopes"`
}

type SecurityConfig struct {
	CORSOrigins    []string        `yaml:"cors_origins"`
	SecureCookies  bool            `yaml:"secure_cookies"`
	CSRFSecret     string          `yaml:"csrf_secret"`
	SessionTimeout time.Duration   `yaml:"session_timeout"`
	MaxUsernameLen int             `yaml:"max_username_length"`
	MaxPasswordLen int             `yaml:"max_password_length"`
	RateLimit      RateLimitConfig `yaml:"rate_limit"`
}

type RateLimitConfig struct {
	LoginAttempts   int           `yaml:"login_attempts"`
	LoginWindow     time.Duration `yaml:"login_window"`
	APIRequests     int           `yaml:"api_requests"`
	APIWindow       time.Duration `yaml:"api_window"`
	CleanupInterval time.Duration `yaml:"cleanup_interval"`
}

func Load() (*Config, error) {
	config := &Config{
		Server: ServerConfig{
			Host:         getEnvOrDefault("SERVER_HOST", "0.0.0.0"),
			Port:         getEnvOrDefault("SERVER_PORT", "8080"),
			Mode:         getEnvOrDefault("SERVER_MODE", "development"),
			BaseURL:      getEnvOrDefault("SERVER_BASE_URL", "http://localhost:8080"),
			BasePath:     getEnvOrDefault("SERVER_BASE_PATH", ""),
			ReadTimeout:  parseDurationOrDefault(getEnvOrDefault("SERVER_READ_TIMEOUT", "30s")),
			WriteTimeout: parseDurationOrDefault(getEnvOrDefault("SERVER_WRITE_TIMEOUT", "30s")),
		},
		Database: DatabaseConfig{
			ConnectionString: getEnvOrSecretOrDefault("DATABASE_URL", "postgres://postgres:password@localhost:5432/redmine?sslmode=disable"),
		},
		Redis: RedisConfig{
			Address:       getEnvOrDefault("REDIS_ADDRESS", "localhost:6379"),
			Username:      getEnvOrDefault("REDIS_USERNAME", ""),
			Password:      getEnvOrSecretOrDefault("REDIS_PASSWORD", ""),
			DB:            parseIntOrDefault(getEnvOrDefault("REDIS_DB", "0")),
			Prefix:        getEnvOrDefault("REDIS_PREFIX", ""),
			UseTLS:        parseBoolOrDefault(getEnvOrDefault("REDIS_USE_TLS", "false")),
			TLSSkipVerify: parseBoolOrDefault(getEnvOrDefault("REDIS_TLS_SKIP_VERIFY", "false")),
		},
		Token: TokenConfig{
			Secret:               getEnvOrSecretOrDefault("TOKEN_SECRET", "your-super-secret-token-key-change-this-in-production"),
			AccessTokenDuration:  parseDurationOrDefault(getEnvOrDefault("ACCESS_TOKEN_DURATION", "10m")),
			RefreshTokenDuration: parseDurationOrDefault(getEnvOrDefault("REFRESH_TOKEN_DURATION", "48h")), // 48 hours
			Issuer:               getEnvOrDefault("TOKEN_ISSUER", "redmine-oauth-service"),
		},
		OAuth: OAuthConfig{
			Issuer:               getEnvOrDefault("OAUTH_ISSUER", "http://localhost:8080"),
			AuthorizationCodeTTL: parseDurationOrDefault(getEnvOrDefault("OAUTH_CODE_TTL", "1m")),
			Clients: []OAuthClientConfig{
				{
					ClientID:     getEnvOrDefault("OAUTH_CLIENT_ID", "lx-vue-app"),
					Name:         getEnvOrDefault("OAUTH_CLIENT_NAME", "LX Vue App"),
					ClientSecret: getEnvOrSecretOrDefault("OAUTH_CLIENT_SECRET", "change-this-secret"),
					ClientType:   getEnvOrDefault("OAUTH_CLIENT_TYPE", "confidential"),
					RedirectURIs: parseCommaSeparatedOrDefault("OAUTH_REDIRECT_URI", "http://localhost:3000/auth/callback"),
					Scopes:       []string{"read", "write"},
				},
			},
		},
		Redmine: RedmineConfig{
			BaseURL:       getEnvOrDefault("REDMINE_BASE_URL", "http://localhost:3000"),
			Timeout:       parseDurationOrDefault(getEnvOrDefault("REDMINE_TIMEOUT", "30s")),
			SecretKeyBase: getEnvOrSecretOrDefault("REDMINE_SECRET_KEY_BASE", ""),
		},
		TwoFactor: TwoFactorConfig{
			Enabled:         parseBoolOrDefault(getEnvOrDefault("TWOFA_ENABLED", "true")),
			SessionTimeout:  parseIntOrDefault(getEnvOrDefault("TWOFA_SESSION_TIMEOUT", "300")),   // 5 minutes
			LockoutDuration: parseIntOrDefault(getEnvOrDefault("TWOFA_LOCKOUT_DURATION", "3600")), // 1 hour
			MaxAttempts:     parseIntOrDefault(getEnvOrDefault("TWOFA_MAX_ATTEMPTS", "3")),
			TrustedProxyIPs: parseCommaSeparatedOrDefault("TRUSTED_PROXY_IPS", ""),
			TOTP: TOTPConfig{
				Issuer: getEnvOrDefault("TOTP_ISSUER", "Redmine Gateway"),
				Period: parseIntOrDefault(getEnvOrDefault("TOTP_PERIOD", "30")),
				Digits: parseIntOrDefault(getEnvOrDefault("TOTP_DIGITS", "6")),
			},
			BackupCode: BackupCodeConfig{
				Length: parseIntOrDefault(getEnvOrDefault("BACKUP_CODE_LENGTH", "8")), // must be 8 to comply with redmine and redmine db restrictions
				Count:  parseIntOrDefault(getEnvOrDefault("BACKUP_CODE_COUNT", "10")),
			},
		},
		ResponseFilter: ResponseFilterConfig{
			Enabled:         parseBoolOrDefault(getEnvOrDefault("RESPONSE_FILTER_ENABLED", "true")),
			SensitiveFields: parseCommaSeparatedOrDefault("RESPONSE_FILTER_SENSITIVE_FIELDS", "api_key,passwd_changed_on,twofa_scheme"),
			PrivacyFields:   parseCommaSeparatedOrDefault("RESPONSE_FILTER_PRIVACY_FIELDS", "last_login_on"),
		},
		Platform: PlatformConfig{
			AutoDetect: parseBoolOrDefault(getEnvOrDefault("PLATFORM_AUTO_DETECT", "true")),
			ForceMode:  getEnvOrDefault("PLATFORM_FORCE_MODE", ""),
		},
		Security: SecurityConfig{
			CORSOrigins:    parseCommaSeparatedOrDefault("CORS_ORIGINS", "http://localhost:3000"),
			SecureCookies:  parseBoolOrDefault(getEnvOrDefault("SECURE_COOKIES", "false")),
			CSRFSecret:     getEnvOrSecretOrDefault("CSRF_SECRET", "your-csrf-secret-change-this-in-production"),
			SessionTimeout: parseDurationOrDefault(getEnvOrDefault("SESSION_TIMEOUT", "15m")),
			MaxUsernameLen: parseIntOrDefault(getEnvOrDefault("MAX_USERNAME_LENGTH", "100")),
			MaxPasswordLen: parseIntOrDefault(getEnvOrDefault("MAX_PASSWORD_LENGTH", "255")),
			RateLimit: RateLimitConfig{
				LoginAttempts:   parseIntOrDefault(getEnvOrDefault("RATE_LIMIT_LOGIN_ATTEMPTS", "5")),
				LoginWindow:     parseDurationOrDefault(getEnvOrDefault("RATE_LIMIT_LOGIN_WINDOW", "15m")),
				APIRequests:     parseIntOrDefault(getEnvOrDefault("RATE_LIMIT_API_REQUESTS", "1000")),
				APIWindow:       parseDurationOrDefault(getEnvOrDefault("RATE_LIMIT_API_WINDOW", "1h")),
				CleanupInterval: parseDurationOrDefault(getEnvOrDefault("RATE_LIMIT_CLEANUP_INTERVAL", "1h")),
			},
		},
		LogLevel:  getEnvOrDefault("LOG_LEVEL", "info"),
		LogFormat: getEnvOrDefault("LOG_FORMAT", "json"),
	}

	// Set LDAP defaults
	config.LDAP.ConnectionTimeout = parseDurationOrDefault(getEnvOrDefault("LDAP_CONNECTION_TIMEOUT", "10s"))
	if config.LDAP.ConnectionTimeout == 0 {
		config.LDAP.ConnectionTimeout = 10 * time.Second
	}
	config.LDAP.RetryAttempts = parseIntOrDefault(getEnvOrDefault("LDAP_RETRY_ATTEMPTS", "1"))
	if config.LDAP.RetryAttempts == 0 {
		config.LDAP.RetryAttempts = 1
	}

	return config, nil
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func parseIntOrDefault(value string) int {
	if i, err := strconv.Atoi(value); err == nil {
		return i
	}
	return 0
}

func parseBoolOrDefault(value string) bool {
	if b, err := strconv.ParseBool(value); err == nil {
		return b
	}
	return false
}

func parseDurationOrDefault(value string) time.Duration {
	if d, err := time.ParseDuration(value); err == nil {
		return d
	}
	return 0
}

func parseCommaSeparatedOrDefault(key, defaultValue string) []string {
	value := getEnvOrDefault(key, defaultValue)
	if value == "" {
		return []string{}
	}

	// Split by comma and trim whitespace
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// getEnvOrSecret reads the environment variable or Docker/Kubernetes secret file content.
func getEnvOrSecret(varName string) string {
	value := os.Getenv(varName)
	if strings.HasPrefix(value, "/") {
		// Check if it's a readable file (works for Docker /run/secrets/, Kubernetes /secret/, etc.)
		if data, err := os.ReadFile(value); err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return value
}

// getEnvOrSecretOrDefault reads env var or secret, with fallback to default
func getEnvOrSecretOrDefault(key, defaultValue string) string {
	if value := getEnvOrSecret(key); value != "" {
		return value
	}
	return defaultValue
}

// GetOAuthClient returns OAuth client configuration by client ID
func (c *Config) GetOAuthClient(clientID string) *OAuthClientConfig {
	for _, client := range c.OAuth.Clients {
		if client.ClientID == clientID {
			return &client
		}
	}
	return nil
}

// IsValidRedirectURI checks if the redirect URI is valid for the client
func (client *OAuthClientConfig) IsValidRedirectURI(redirectURI string) bool {
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			return true
		}
	}
	return false
}
