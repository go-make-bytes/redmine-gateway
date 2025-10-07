package logger

import (
	"os"

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
			TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
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
