package logger

import (
	"os"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	globalLogger *zap.Logger
	sugarLogger  *zap.SugaredLogger
	once         sync.Once
)

type Config struct {
	Level      string
	Format     string
	OutputPath string
}

func Init(cfg *Config) error {
	var err error
	once.Do(func() {
		err = initLogger(cfg)
	})
	return err
}

func initLogger(cfg *Config) error {
	var level zapcore.Level
	switch cfg.Level {
	case "debug":
		level = zapcore.DebugLevel
	case "info":
		level = zapcore.InfoLevel
	case "warn":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	default:
		level = zapcore.InfoLevel
	}

	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	var encoder zapcore.Encoder
	if cfg.Format == "json" {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	} else {
		encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	}

	var writeSyncer zapcore.WriteSyncer
	if cfg.OutputPath != "" && cfg.OutputPath != "stdout" {
		file, err := os.OpenFile(cfg.OutputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			writeSyncer = zapcore.AddSync(os.Stdout)
		} else {
			writeSyncer = zapcore.AddSync(file)
		}
	} else {
		writeSyncer = zapcore.AddSync(os.Stdout)
	}

	core := zapcore.NewCore(encoder, writeSyncer, level)
	globalLogger = zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))
	sugarLogger = globalLogger.Sugar()

	return nil
}

func L() *zap.Logger {
	if globalLogger == nil {
		Init(&Config{Level: "info", Format: "json"})
	}
	return globalLogger
}

func S() *zap.SugaredLogger {
	if sugarLogger == nil {
		Init(&Config{Level: "info", Format: "json"})
	}
	return sugarLogger
}

func Sync() error {
	if globalLogger != nil {
		return globalLogger.Sync()
	}
	return nil
}

func Debug(msg string, fields ...zap.Field) {
	L().Debug(msg, fields...)
}

func Info(msg string, fields ...zap.Field) {
	L().Info(msg, fields...)
}

func Warn(msg string, fields ...zap.Field) {
	L().Warn(msg, fields...)
}

func Error(msg string, fields ...zap.Field) {
	L().Error(msg, fields...)
}

func Fatal(msg string, fields ...zap.Field) {
	L().Fatal(msg, fields...)
}

func With(fields ...zap.Field) *zap.Logger {
	return L().With(fields...)
}

func RequestLogger(method, path, requestID string, statusCode int, latencyMs int64, userID string) {
	Info("request",
		zap.String("method", method),
		zap.String("path", path),
		zap.String("request_id", requestID),
		zap.Int("status", statusCode),
		zap.Int64("latency_ms", latencyMs),
		zap.String("user", userID),
	)
}

func AuditLogger(action, resource, userID, result string, details map[string]interface{}) {
	fields := []zap.Field{
		zap.String("action", action),
		zap.String("resource", resource),
		zap.String("user", userID),
		zap.String("result", result),
	}
	for k, v := range details {
		fields = append(fields, zap.Any(k, v))
	}
	Info("audit", fields...)
}

func ErrorLogger(err error, context map[string]interface{}) {
	fields := []zap.Field{
		zap.Error(err),
	}
	for k, v := range context {
		fields = append(fields, zap.Any(k, v))
	}
	Error("error", fields...)
}
