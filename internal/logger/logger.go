// Package logger provides internal logging functionality for cryptum-go.
package logger

import (
	"fmt"
	"log"
	"os"
	"sync"
)

// Level represents the logging level
type Level int

const (
	// DEBUG level for detailed information
	DEBUG Level = iota
	// INFO level for general information
	INFO
	// WARN level for warning messages
	WARN
	// ERROR level for error messages
	ERROR
	// FATAL level for fatal errors
	FATAL
)

// Logger provides thread-safe logging functionality
type Logger struct {
	*log.Logger
	level Level
}

var (
	instance *Logger
	once     sync.Once
)

// Field represents a key-value pair for structured logging
type Field struct {
	Key   string
	Value interface{}
}

// StringField creates a new Field with a string value
func StringField(key string, value string) Field {
	return Field{Key: key, Value: value}
}

// IntField creates a new Field with an int value
func IntField(key string, value int) Field {
	return Field{Key: key, Value: value}
}

// GetInstance returns the singleton logger instance
func GetInstance() *Logger {
	once.Do(func() {
		instance = &Logger{
			Logger: log.New(os.Stderr, "", log.LstdFlags),
			level:  INFO,
		}
	})
	return instance
}

// SetLevel sets the logging level
func (l *Logger) SetLevel(level Level) {
	l.level = level
}

// Debug logs a debug message with optional fields
func (l *Logger) Debug(msg string, fields ...Field) {
	if l.level <= DEBUG {
		l.log("DEBUG", msg, fields...)
	}
}

// Info logs an info message with optional fields
func (l *Logger) Info(msg string, fields ...Field) {
	if l.level <= INFO {
		l.log("INFO", msg, fields...)
	}
}

// Warn logs a warning message with optional fields
func (l *Logger) Warn(msg string, fields ...Field) {
	if l.level <= WARN {
		l.log("WARN", msg, fields...)
	}
}

// Error logs an error message with optional fields
func (l *Logger) Error(msg string, fields ...Field) {
	if l.level <= ERROR {
		l.log("ERROR", msg, fields...)
	}
}

// Fatal logs a fatal message with optional fields and exits
func (l *Logger) Fatal(msg string, fields ...Field) {
	if l.level <= FATAL {
		l.log("FATAL", msg, fields...)
		os.Exit(1)
	}
}

// log formats and writes the log message
func (l *Logger) log(level string, msg string, fields ...Field) {
	if len(fields) == 0 {
		l.Printf("[%s] %s", level, msg)
		return
	}

	// Format fields
	fieldStr := ""
	for _, f := range fields {
		fieldStr += " " + f.Key + "=" + formatValue(f.Value)
	}
	l.Printf("[%s] %s%s", level, msg, fieldStr)
}

// formatValue converts a value to its string representation
func formatValue(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}
