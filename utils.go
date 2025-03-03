package caddyipinfofree

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"

	"github.com/go-co-op/gocron/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"
)

func generateSha256ForFile(filepath string) (string, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	currentChecksum := sha256.New()
	if _, err := io.Copy(currentChecksum, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(currentChecksum.Sum(nil)), nil
}

func errorToLogsWrapper(l *zap.Logger, f func() error) func() {
	return func() {
		if err := f(); err != nil {
			l.Error(err.Error())
		}
	}
}

// This is required to make the caddy internal logger compatiable with the gocron library
type zapGocronLogger struct {
	logger *slog.Logger
}

func newZapGocronLogger(name string, logger *zap.Logger) *zapGocronLogger {
	return &zapGocronLogger{logger: slog.New(zapslog.NewHandler(logger.Core(), zapslog.WithName(name)))}
}

func (l *zapGocronLogger) Debug(msg string, args ...any) {
	l.logger.Debug(msg, args...)
}

func (l *zapGocronLogger) Error(msg string, args ...any) {
	l.logger.Error(msg, args...)
}

func (l *zapGocronLogger) Info(msg string, args ...any) {
	l.logger.Info(msg, args...)
}

func (l *zapGocronLogger) Warn(msg string, args ...any) {
	l.logger.Warn(msg, args...)
}

var (
	_ gocron.Logger = (*zapGocronLogger)(nil)
)
