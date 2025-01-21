package logger

import (
	"bytes"
	"strings"
	"testing"
)

func TestLogger(t *testing.T) {
	// Override exit function
	oldExitFunc := ExitFunc
	ExitFunc = func(code int) {} // No-op for tests
	defer func() {
		ExitFunc = oldExitFunc
	}()

	// Reset and set up logger
	ResetInstance()
	var buf bytes.Buffer
	instance := GetInstance()
	instance.SetOutput(&buf)

	tests := []struct {
		name     string
		level    Level
		logFunc  func(string, ...Field)
		message  string
		fields   []Field
		wantLog  bool
		contains string
	}{
		{
			name:     "Debug message with level DEBUG",
			level:    DEBUG,
			logFunc:  instance.Debug,
			message:  "debug message",
			fields:   []Field{StringField("key", "value")},
			wantLog:  true,
			contains: "[DEBUG] debug message key=value",
		},
		{
			name:     "Debug message with level INFO",
			level:    INFO,
			logFunc:  instance.Debug,
			message:  "debug message",
			wantLog:  false,
			contains: "",
		},
		{
			name:     "Info message",
			level:    INFO,
			logFunc:  instance.Info,
			message:  "info message",
			fields:   []Field{IntField("count", 42)},
			wantLog:  true,
			contains: "[INFO] info message count=42",
		},
		{
			name:     "Warn message",
			level:    WARN,
			logFunc:  instance.Warn,
			message:  "warn message",
			wantLog:  true,
			contains: "[WARN] warn message",
		},
		{
			name:     "Error message",
			level:    ERROR,
			logFunc:  instance.Error,
			message:  "error message",
			wantLog:  true,
			contains: "[ERROR] error message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			instance.SetLevel(tt.level)
			tt.logFunc(tt.message, tt.fields...)

			got := buf.String()
			if tt.wantLog {
				if !strings.Contains(got, tt.contains) {
					t.Errorf("Logger output = %q, want to contain %q", got, tt.contains)
				}
			} else {
				if got != "" {
					t.Errorf("Logger output = %q, want empty string", got)
				}
			}
		})
	}
}

func TestFormatValue(t *testing.T) {
	tests := []struct {
		name  string
		value interface{}
		want  string
	}{
		{
			name:  "String value",
			value: "test",
			want:  "test",
		},
		{
			name:  "Integer value",
			value: 42,
			want:  "42",
		},
		{
			name:  "Boolean value",
			value: true,
			want:  "true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatValue(tt.value); got != tt.want {
				t.Errorf("formatValue() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetInstance(t *testing.T) {
	ResetInstance()
	logger1 := GetInstance()
	logger2 := GetInstance()

	if logger1 != logger2 {
		t.Error("GetInstance() returned different instances")
	}
}

func TestSetOutput(t *testing.T) {
	// Override exit function
	oldExitFunc := ExitFunc
	ExitFunc = func(code int) {} // No-op for tests
	defer func() {
		ExitFunc = oldExitFunc
	}()

	// Reset logger instance
	ResetInstance()

	var buf bytes.Buffer
	instance := GetInstance()
	instance.SetOutput(&buf)

	testMessage := "test output"
	instance.Info(testMessage)

	expected := "[INFO] " + testMessage + "\n"
	if got := buf.String(); got != expected {
		t.Errorf("Expected output %q, got %q", expected, got)
	}
}

func TestResetInstance(t *testing.T) {
	// Get initial instance and modify it
	instance1 := GetInstance()
	instance1.SetLevel(DEBUG)

	// Reset instance
	ResetInstance()

	// Get new instance
	instance2 := GetInstance()

	// Verify it's a new instance with default settings
	if instance1 == instance2 {
		t.Error("ResetInstance() did not create a new instance")
	}

	if instance2.level != INFO {
		t.Errorf("New instance has level %v, want %v", instance2.level, INFO)
	}
}

func TestMoreFieldTypes(t *testing.T) {
	// Override exit function
	oldExitFunc := ExitFunc
	ExitFunc = func(code int) {} // No-op for tests
	defer func() {
		ExitFunc = oldExitFunc
	}()

	// Reset logger instance
	ResetInstance()

	var buf bytes.Buffer
	instance := GetInstance()
	instance.SetOutput(&buf)

	tests := []struct {
		name     string
		field    Field
		contains string
	}{
		{
			name:     "Float field",
			field:    Field{"float", 3.14},
			contains: "float=3.14",
		},
		{
			name:     "Array field",
			field:    Field{"array", []string{"a", "b"}},
			contains: "array=[a b]",
		},
		{
			name:     "Map field",
			field:    Field{"map", map[string]int{"a": 1}},
			contains: "map=map[a:1]",
		},
		{
			name:     "Nil field",
			field:    Field{"nil", nil},
			contains: "nil=<nil>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			instance.Info("test message", tt.field)

			if !strings.Contains(buf.String(), tt.contains) {
				t.Errorf("Expected output to contain %q, got %q", tt.contains, buf.String())
			}
		})
	}
}

func TestExitFuncError(t *testing.T) {
	// Reset logger instance
	ResetInstance()

	var buf bytes.Buffer
	instance := GetInstance()
	instance.SetOutput(&buf)

	// Override exit function
	oldExitFunc := ExitFunc
	exitCode := -1
	ExitFunc = func(code int) {
		exitCode = code
	}
	defer func() {
		ExitFunc = oldExitFunc
	}()

	// Test error with exit
	errorMsg := "fatal error"
	instance.Error(errorMsg)

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}

	expected := "[ERROR] " + errorMsg + "\n"
	if got := buf.String(); got != expected {
		t.Errorf("Expected output %q, got %q", expected, got)
	}
}

func TestLogLevelChanges(t *testing.T) {
	// Override exit function
	oldExitFunc := ExitFunc
	ExitFunc = func(code int) {} // No-op for tests
	defer func() {
		ExitFunc = oldExitFunc
	}()

	// Reset logger instance
	ResetInstance()

	var buf bytes.Buffer
	instance := GetInstance()
	instance.SetOutput(&buf)

	tests := []struct {
		name      string
		setLevel  Level
		logLevel  Level
		logFunc   func(string, ...Field)
		shouldLog bool
	}{
		{
			name:      "Debug when level is Info",
			setLevel:  INFO,
			logLevel:  DEBUG,
			logFunc:   instance.Debug,
			shouldLog: false,
		},
		{
			name:      "Info when level is Debug",
			setLevel:  DEBUG,
			logLevel:  INFO,
			logFunc:   instance.Info,
			shouldLog: true,
		},
		{
			name:      "Error when level is Warn",
			setLevel:  WARN,
			logLevel:  ERROR,
			logFunc:   instance.Error,
			shouldLog: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			instance.SetLevel(tt.setLevel)

			tt.logFunc("test message")

			hasOutput := buf.Len() > 0
			if hasOutput != tt.shouldLog {
				t.Errorf("Expected log output=%v, got output=%v", tt.shouldLog, hasOutput)
			}
		})
	}
}
