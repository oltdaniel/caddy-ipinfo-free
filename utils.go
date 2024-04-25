package caddyipinfofree

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
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

func errorToLogsWrapper(l *slog.Logger, f func() error) func() {
	return func() {
		if err := f(); err != nil {
			l.Error(err.Error())
		}
	}
}
