/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package logger

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/CESSProject/cess-go-sdk/core/pattern"
	"github.com/natefinch/lumberjack"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger interface {
	Log(string, string)
	Pnc(msg string)
	Upfile(string, string)
	Downfile(string, string)
	Del(string, string)
	Track(string, string)
	Query(string, string)
	Discover(string, string)
}

type logs struct {
	logpath map[string]string
	log     map[string]*zap.Logger
}

// log file
var (
	LogFiles = []string{
		"log",      //General log
		"panic",    //Panic log
		"upfile",   //Upload file log
		"downfile", //Download log
		"delete",
		"track",
		"query",
		"discover",
	}
)

func NewLogs(logfiles map[string]string) (Logger, error) {
	var (
		logpath = make(map[string]string, 0)
		logCli  = make(map[string]*zap.Logger)
	)
	for name, fpath := range logfiles {
		dir := getFilePath(fpath)
		_, err := os.Stat(dir)
		if err != nil {
			err = os.MkdirAll(dir, pattern.DirMode)
			if err != nil {
				return nil, errors.Errorf("%v,%v", dir, err)
			}
		}
		Encoder := getEncoder()
		newCore := zapcore.NewTee(
			zapcore.NewCore(Encoder, getWriteSyncer(fpath), zap.NewAtomicLevel()),
		)
		logpath[name] = fpath
		logCli[name] = zap.New(newCore, zap.AddCaller())
		logCli[name].Sugar().Infof("%v", fpath)
	}
	return &logs{
		logpath: logpath,
		log:     logCli,
	}, nil
}

func (l *logs) Log(level string, msg string) {
	_, file, line, _ := runtime.Caller(1)
	v, ok := l.log["log"]
	if ok {
		switch level {
		case "info":
			v.Sugar().Infof("[%v:%d] %v", filepath.Base(file), line, msg)
		case "err":
			v.Sugar().Errorf("[%v:%d] %v", filepath.Base(file), line, msg)
		}
	}
}

func (l *logs) Pnc(msg string) {
	_, file, line, _ := runtime.Caller(1)
	v, ok := l.log["panic"]
	if ok {
		v.Sugar().Errorf("[%s:%d] %s", filepath.Base(file), line, msg)
	}
}

func (l *logs) Upfile(level string, msg string) {
	_, file, line, _ := runtime.Caller(1)
	v, ok := l.log["upfile"]
	if ok {
		switch level {
		case "info":
			v.Sugar().Infof("[%v:%d] %s", filepath.Base(file), line, msg)
		case "err":
			v.Sugar().Errorf("[%v:%d] %s", filepath.Base(file), line, msg)
		}
	}
}

func (l *logs) Downfile(level string, msg string) {
	_, file, line, _ := runtime.Caller(1)
	v, ok := l.log["downfile"]
	if ok {
		switch level {
		case "info":
			v.Sugar().Infof("[%v:%d] %v", filepath.Base(file), line, msg)
		case "err":
			v.Sugar().Errorf("[%v:%d] %v", filepath.Base(file), line, msg)
		}
	}
}

func (l *logs) Del(level string, msg string) {
	_, file, line, _ := runtime.Caller(1)
	v, ok := l.log["delete"]
	if ok {
		switch level {
		case "info":
			v.Sugar().Infof("[%v:%d] %v", filepath.Base(file), line, msg)
		case "err":
			v.Sugar().Errorf("[%v:%d] %v", filepath.Base(file), line, msg)
		}
	}
}

func (l *logs) Track(level string, msg string) {
	_, file, line, _ := runtime.Caller(1)
	v, ok := l.log["track"]
	if ok {
		switch level {
		case "info":
			v.Sugar().Infof("[%v:%d] %v", filepath.Base(file), line, msg)
		case "err":
			v.Sugar().Errorf("[%v:%d] %v", filepath.Base(file), line, msg)
		}
	}
}

func (l *logs) Query(level string, msg string) {
	_, file, line, _ := runtime.Caller(1)
	v, ok := l.log["query"]
	if ok {
		switch level {
		case "info":
			v.Sugar().Infof("[%v:%d] %v", filepath.Base(file), line, msg)
		case "err":
			v.Sugar().Errorf("[%v:%d] %v", filepath.Base(file), line, msg)
		}
	}
}

func (l *logs) Discover(level, msg string) {
	_, file, line, _ := runtime.Caller(1)
	v, ok := l.log["discover"]
	if ok {
		switch level {
		case "info":
			v.Sugar().Infof("[%v:%d] %v", filepath.Base(file), line, msg)
		case "err":
			v.Sugar().Errorf("[%v:%d] %v", filepath.Base(file), line, msg)
		}
	}
}

func getFilePath(fpath string) string {
	path, _ := filepath.Abs(fpath)
	index := strings.LastIndex(path, string(os.PathSeparator))
	ret := path[:index]
	return ret
}

func getEncoder() zapcore.Encoder {
	return zapcore.NewConsoleEncoder(
		zapcore.EncoderConfig{
			TimeKey:        "ts",
			LevelKey:       "level",
			NameKey:        "logger",
			CallerKey:      "caller_line",
			FunctionKey:    zapcore.OmitKey,
			MessageKey:     "msg",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    cEncodeLevel,
			EncodeTime:     cEncodeTime,
			EncodeDuration: zapcore.SecondsDurationEncoder,
			EncodeCaller:   nil,
		})
}

func getWriteSyncer(fpath string) zapcore.WriteSyncer {
	lumberJackLogger := &lumberjack.Logger{
		Filename:   fpath,
		MaxSize:    5,
		MaxBackups: 10,
		MaxAge:     30,
		LocalTime:  true,
		Compress:   true,
	}
	return zapcore.AddSync(lumberJackLogger)
}

func cEncodeLevel(level zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString("[" + level.CapitalString() + "]")
}

func cEncodeTime(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString("[" + t.Format("2006-01-02 15:04:05") + "]")
}
