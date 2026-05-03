// Package logging is a thin level-aware wrapper around the stdlib logger.
// We intentionally avoid pulling in zap/zerolog: a security audit tool
// should be auditable itself, and stdlib keeps the dependency surface flat.
package logging

import (
	"io"
	"log"
	"os"
	"strings"
)

// Level is the verbosity threshold.
type Level int

const (
	LevelError Level = iota
	LevelWarn
	LevelInfo
	LevelDebug
)

// ParseLevel parses "error"|"warn"|"info"|"debug" (case-insensitive).
func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug", "d":
		return LevelDebug
	case "info", "i":
		return LevelInfo
	case "warn", "warning", "w":
		return LevelWarn
	default:
		return LevelError
	}
}

// Logger is a structured-ish wrapper. It writes to stderr by default
// so that stdout remains reserved for machine-readable output (JSON, MD).
type Logger struct {
	level Level
	std   *log.Logger
}

// New returns a logger writing to stderr at the given level.
func New(level Level) *Logger {
	return &Logger{
		level: level,
		std:   log.New(os.Stderr, "escape: ", log.Ltime),
	}
}

// NewWithWriter is mostly useful in tests.
func NewWithWriter(level Level, w io.Writer) *Logger {
	return &Logger{
		level: level,
		std:   log.New(w, "escape: ", 0),
	}
}

// Discard returns a logger that drops every message.
func Discard() *Logger {
	return NewWithWriter(LevelError, io.Discard)
}

func (l *Logger) Errorf(format string, args ...any) {
	if l == nil || l.level < LevelError {
		return
	}
	l.std.Printf("ERROR "+format, args...)
}
func (l *Logger) Warnf(format string, args ...any) {
	if l == nil || l.level < LevelWarn {
		return
	}
	l.std.Printf("WARN  "+format, args...)
}
func (l *Logger) Infof(format string, args ...any) {
	if l == nil || l.level < LevelInfo {
		return
	}
	l.std.Printf("INFO  "+format, args...)
}
func (l *Logger) Debugf(format string, args ...any) {
	if l == nil || l.level < LevelDebug {
		return
	}
	l.std.Printf("DEBUG "+format, args...)
}
