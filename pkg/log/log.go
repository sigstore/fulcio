// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package log

import (
	"context"
	"log"

	"github.com/goadesign/goa/grpc/middleware"
	grpc_zap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

// Logger set the default logger to development mode
var Logger *zap.SugaredLogger

func init() {
	ConfigureLogger("dev")
}

func ConfigureLogger(logType string) {
	var cfg zap.Config
	if logType == "prod" {
		cfg = zap.NewProductionConfig()
		cfg.EncoderConfig.LevelKey = "severity"
		cfg.EncoderConfig.MessageKey = "message"
	} else {
		cfg = zap.NewDevelopmentConfig()
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}
	logger, err := cfg.Build()
	if err != nil {
		log.Fatalln("createLogger", err)
	}
	Logger = logger.Sugar()
}

var CliLogger = createCliLogger()

func createCliLogger() *zap.SugaredLogger {
	cfg := zap.NewDevelopmentConfig()
	cfg.EncoderConfig.TimeKey = ""
	cfg.EncoderConfig.LevelKey = ""
	cfg.DisableCaller = true
	logger, err := cfg.Build()
	if err != nil {
		log.Fatalln("createLogger", err)
	}

	return logger.Sugar()
}

type requestIDMetadataKeyType string

const (
	requestIDMetadataKey requestIDMetadataKeyType = middleware.RequestIDMetadataKey
)

func ContextLogger(ctx context.Context) *zap.SugaredLogger {
	proposedLogger := Logger
	if ctx != nil {
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			val := md.Get(string(requestIDMetadataKey))
			if len(val) == 1 {
				proposedLogger = proposedLogger.With(zap.String("requestID", val[0]))
			}
		}
	}

	return proposedLogger
}

func SetupGRPCLogging() (*zap.Logger, []grpc_zap.Option) {
	var options []grpc_zap.Option
	options = append(options, grpc_zap.WithDecider(func(methodName string, err error) bool {
		// TODO: implement filters to eliminate health check log statements
		return true
	}))
	options = append(options, grpc_zap.WithMessageProducer(
		func(ctx context.Context, msg string, level zapcore.Level, code codes.Code, err error, duration zapcore.Field) {
			var requestID zap.Field
			if md, ok := metadata.FromIncomingContext(ctx); ok {
				val := md.Get(string(requestIDMetadataKey))
				if len(val) == 1 {
					requestID = zap.String("requestID", val[0])
				}
			}
			ctxzap.Extract(ctx).Debug(msg, zap.Error(err), zap.String("grpc.code", code.String()), requestID, duration)
		}))
	return Logger.Desugar(), options
}
