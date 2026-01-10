package logger

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/takehaya/vinbero/pkg/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func NewLogger(cfg config.LoggerConfig) (*zap.Logger, func(context.Context) error, error) {
	encCfg := zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		MessageKey:     "msg",
		CallerKey:      "caller",
		EncodeTime:     func(t time.Time, enc zapcore.PrimitiveArrayEncoder) { enc.AppendString(t.Format(time.RFC3339)) },
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	var enc zapcore.Encoder
	if strings.ToLower(cfg.Format) == "json" {
		enc = zapcore.NewJSONEncoder(encCfg)
	} else {
		if cfg.NoColor || runtime.GOOS == "windows" {
			encCfg.EncodeLevel = zapcore.CapitalLevelEncoder
		} else {
			encCfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
		}
		enc = zapcore.NewConsoleEncoder(encCfg)
	}

	level, err := parseLogLevel(cfg.Level)
	if err != nil {
		return nil, nil, err
	}

	ws := zapcore.AddSync(os.Stderr)
	core := zapcore.NewCore(enc, ws, level)

	opts := []zap.Option{
		zap.ErrorOutput(ws),
		zap.AddStacktrace(zapcore.ErrorLevel),
	}
	if cfg.AddCaller || level == zapcore.DebugLevel {
		opts = append(opts, zap.AddCaller())
	}

	lg := zap.New(core, opts...)

	cleanup := func(_ context.Context) error {
		if err := lg.Sync(); err != nil {
			if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EBADF) {
				return nil
			}
			return err
		}
		return nil
	}
	return lg, cleanup, nil
}

func parseLogLevel(level string) (zapcore.Level, error) {
	switch strings.ToLower(level) {
	case "debug":
		return zapcore.DebugLevel, nil
	case "info", "":
		return zapcore.InfoLevel, nil
	case "warn", "warning":
		return zapcore.WarnLevel, nil
	case "error":
		return zapcore.ErrorLevel, nil
	default:
		return zapcore.InfoLevel, fmt.Errorf("invalid log level: %s", level)
	}
}
