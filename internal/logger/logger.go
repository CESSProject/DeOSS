package logger

import (
	"cess-gateway/configs"
	"fmt"
	"os"
	"time"

	"github.com/natefinch/lumberjack"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	Err  *zap.Logger
	Out  *zap.Logger
	Uld  *zap.Logger
	path string
)

func Log_Init() {
	f, err := os.Stat(configs.LogfileDir)
	if err != nil {
		err = os.MkdirAll(configs.LogfileDir, os.ModeDir)
		if err != nil {
			path = "./log"
		} else {
			path = configs.LogfileDir
		}
	} else {
		if f.IsDir() {
			path = configs.LogfileDir
		} else {
			err = os.RemoveAll(configs.LogfileDir)
			if err != nil {
				fmt.Printf("\x1b[%dm[err]\x1b[0m %v\n", 41, err)
				os.Exit(1)
			}
			err = os.MkdirAll(configs.LogfileDir, os.ModeDir)
			if err != nil {
				path = "./log"
			} else {
				path = configs.LogfileDir
			}
		}
	}
	initOutLogger()
	initErrLogger()
	initUldLogger()
}

// out log
func initOutLogger() {
	outlogpath := path + "/out.log"
	hook := lumberjack.Logger{
		Filename:   outlogpath,
		MaxSize:    30,  //MB
		MaxAge:     365, //Day
		MaxBackups: 0,
		LocalTime:  true,
		Compress:   true,
	}
	encoderConfig := zapcore.EncoderConfig{
		MessageKey:   "msg",
		TimeKey:      "time",
		CallerKey:    "file",
		LineEnding:   zapcore.DefaultLineEnding,
		EncodeLevel:  zapcore.LowercaseLevelEncoder,
		EncodeTime:   formatEncodeTime,
		EncodeCaller: zapcore.ShortCallerEncoder,
	}
	atomicLevel := zap.NewAtomicLevel()
	atomicLevel.SetLevel(zap.InfoLevel)
	var writes = []zapcore.WriteSyncer{zapcore.AddSync(&hook)}
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		zapcore.NewMultiWriteSyncer(writes...),
		atomicLevel,
	)
	caller := zap.AddCaller()
	development := zap.Development()
	Out = zap.New(core, caller, development)
	Out.Sugar().Errorf("The service has started and created a log file in the %v", outlogpath)
}

// error log
func initErrLogger() {
	errlogpath := path + "/error.log"
	hook := lumberjack.Logger{
		Filename:   errlogpath,
		MaxSize:    20,  //MB
		MaxAge:     365, //Day
		MaxBackups: 0,
		LocalTime:  true,
		Compress:   true,
	}
	encoderConfig := zapcore.EncoderConfig{
		MessageKey:   "msg",
		TimeKey:      "time",
		CallerKey:    "file",
		LineEnding:   zapcore.DefaultLineEnding,
		EncodeLevel:  zapcore.LowercaseLevelEncoder,
		EncodeTime:   formatEncodeTime,
		EncodeCaller: zapcore.ShortCallerEncoder,
	}
	atomicLevel := zap.NewAtomicLevel()
	atomicLevel.SetLevel(zap.ErrorLevel)
	var writes = []zapcore.WriteSyncer{zapcore.AddSync(&hook)}
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		zapcore.NewMultiWriteSyncer(writes...),
		atomicLevel,
	)
	caller := zap.AddCaller()
	development := zap.Development()
	Err = zap.New(core, caller, development)
	Err.Sugar().Errorf("The service has started and created a log file in the %v", errlogpath)
}

// out log
func initUldLogger() {
	uldlogpath := path + "/uld.log"
	hook := lumberjack.Logger{
		Filename:   uldlogpath,
		MaxSize:    10,  //MB
		MaxAge:     365, //Day
		MaxBackups: 0,
		LocalTime:  true,
		Compress:   true,
	}
	encoderConfig := zapcore.EncoderConfig{
		MessageKey:   "msg",
		TimeKey:      "time",
		CallerKey:    "file",
		LineEnding:   zapcore.DefaultLineEnding,
		EncodeLevel:  zapcore.LowercaseLevelEncoder,
		EncodeTime:   formatEncodeTime,
		EncodeCaller: zapcore.ShortCallerEncoder,
	}
	atomicLevel := zap.NewAtomicLevel()
	atomicLevel.SetLevel(zap.InfoLevel)
	var writes = []zapcore.WriteSyncer{zapcore.AddSync(&hook)}
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		zapcore.NewMultiWriteSyncer(writes...),
		atomicLevel,
	)
	caller := zap.AddCaller()
	development := zap.Development()
	Uld = zap.New(core, caller, development)
	Uld.Sugar().Errorf("The service has started and created a log file in the %v", uldlogpath)
}

func formatEncodeTime(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(fmt.Sprintf("%d-%02d-%02d %02d:%02d:%02d", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second()))
}
