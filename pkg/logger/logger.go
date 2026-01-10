package logger

import (
	"context"
	"errors"
	"os"
	"runtime"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Config struct {
	JSON      bool `default:"false"` // if true, use JSON format
	NoColor   bool `default:"false"` // if true, disable color output
	Verbose   int  `default:"0"`     // 0 is Info level, 1 or higher is Debug
	Quiet     bool `default:"false"` // if true, raise to Warn level or higher
	AddCaller bool `default:"false"` // if true, add caller information to logs
}

func NewLogger(cfg Config) (*zap.Logger, func(context.Context) error, error) {
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
	if cfg.JSON {
		enc = zapcore.NewJSONEncoder(encCfg)
	} else {
		if cfg.NoColor || runtime.GOOS == "windows" {
			encCfg.EncodeLevel = zapcore.CapitalLevelEncoder
		} else {
			encCfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
		}
		enc = zapcore.NewConsoleEncoder(encCfg)
	}

	// Output logs to stderr for CLI
	ws := zapcore.AddSync(os.Stderr)

	level := zapcore.InfoLevel
	if cfg.Quiet {
		level = zapcore.WarnLevel
	}
	if cfg.Verbose > 0 && !cfg.Quiet {
		level = zapcore.DebugLevel
	}

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
			// Ignore Sync errors for stdout/stderr as they often result in EINVAL etc. in many environments
			if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EBADF) {
				return nil
			}
			return err
		}
		return nil
	}
	return lg, cleanup, nil
}
