package logger

import (
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

type Logger struct {
	*logrus.Logger
}

func New(level, format string) *Logger {
	log := logrus.New()

	// Set log level
	switch level {
	case "debug":
		log.SetLevel(logrus.DebugLevel)
	case "info":
		log.SetLevel(logrus.InfoLevel)
	case "warn":
		log.SetLevel(logrus.WarnLevel)
	case "error":
		log.SetLevel(logrus.ErrorLevel)
	default:
		log.SetLevel(logrus.InfoLevel)
	}

	// Set log format
	if format == "json" {
		log.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat:   "2006-01-02T15:04:05.000Z07:00",
			DisableHTMLEscape: true,
			PrettyPrint:       false,
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
			},
		})
	} else {
		log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
		})
	}

	log.SetOutput(os.Stdout)

	return &Logger{Logger: log}
}

// WithRequestID adds request ID to log context
func (l *Logger) WithRequestID(requestID string) *logrus.Entry {
	return l.Logger.WithField("request_id", requestID)
}

// WithUserID adds user ID to log context
func (l *Logger) WithUserID(userID int) *logrus.Entry {
	return l.Logger.WithField("user_id", userID)
}

// WithClientIP adds client IP to log context
func (l *Logger) WithClientIP(clientIP string) *logrus.Entry {
	return l.Logger.WithField("client_ip", clientIP)
}

// SecurityLog logs security-related events
func (l *Logger) SecurityLog(event string, userID int, clientIP string, details map[string]interface{}) {
	entry := l.Logger.WithFields(logrus.Fields{
		"event_type": "security",
		"event":      event,
		"user_id":    userID,
		"client_ip":  clientIP,
	})

	for key, value := range details {
		entry = entry.WithField(key, value)
	}

	entry.Info("Security event")
}

// OAuthLog logs OAuth-related events
func (l *Logger) OAuthLog(event string, clientID string, userID int, details map[string]interface{}) {
	entry := l.Logger.WithFields(logrus.Fields{
		"event_type": "oauth",
		"event":      event,
		"client_id":  clientID,
		"user_id":    userID,
	})

	for key, value := range details {
		entry = entry.WithField(key, value)
	}

	entry.Info("OAuth event")
}

// TwoFAAuditLog logs 2FA-specific audit events with structured data
func (l *Logger) TwoFAAuditLog(event string, userID int, username, clientIP string, details map[string]interface{}) {
	entry := l.Logger.WithFields(logrus.Fields{
		"event_type": "audit",
		"audit_type": "twofa",
		"event":      event,
		"user_id":    userID,
		"username":   username,
		"client_ip":  clientIP,
		"timestamp":  time.Now().Unix(),
		"service":    "redmine-gateway",
	})

	// Add event-specific fields
	for key, value := range details {
		entry = entry.WithField(key, value)
	}

	// Use appropriate log level based on event severity
	switch event {
	case "twofa_enrollment_completed", "twofa_verification_success", "twofa_disabled":
		entry.Info("2FA audit event")
	case "twofa_verification_failed", "twofa_rate_limit_exceeded", "twofa_account_locked":
		entry.Warn("2FA audit event")
	case "twofa_security_violation", "twofa_suspicious_activity":
		entry.Error("2FA audit event")
	default:
		entry.Info("2FA audit event")
	}
}

// TwoFAEnrollmentAudit logs 2FA enrollment events
func (l *Logger) TwoFAEnrollmentAudit(userID int, username, clientIP, action string, details map[string]interface{}) {
	details["action"] = action
	l.TwoFAAuditLog("twofa_enrollment_"+action, userID, username, clientIP, details)
}

// TwoFAVerificationAudit logs 2FA verification attempts
func (l *Logger) TwoFAVerificationAudit(userID int, username, clientIP string, success bool, method string, details map[string]interface{}) {
	event := "twofa_verification_success"
	if !success {
		event = "twofa_verification_failed"
	}

	details["method"] = method // "totp", "backup_code"
	details["success"] = success
	l.TwoFAAuditLog(event, userID, username, clientIP, details)
}

// TwoFAManagementAudit logs 2FA management operations
func (l *Logger) TwoFAManagementAudit(userID int, username, clientIP, operation string, details map[string]interface{}) {
	details["operation"] = operation
	l.TwoFAAuditLog("twofa_management_"+operation, userID, username, clientIP, details)
}
