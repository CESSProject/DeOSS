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

	"github.com/natefinch/lumberjack"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger interface {
	Log(string, string)
	Pnc(msg string)
	Logput(string, string)
	Logget(string, string)
	Logdown(string, string)
	Logopen(string, string)
	Logdel(string, string)
	Logtrack(string, string)
	Logpart(string, string)
	Logfull(string, string)
	Logrange(string, string)
}

type logs struct {
	logpath   map[string]string
	log_log   *zap.Logger
	log_pnc   *zap.Logger
	log_put   *zap.Logger
	log_get   *zap.Logger
	log_down  *zap.Logger
	log_open  *zap.Logger
	log_del   *zap.Logger
	log_track *zap.Logger
	log_part  *zap.Logger
	log_full  *zap.Logger
	log_range *zap.Logger
}

// log file
var (
	LogFiles = []string{
		"log",      // general log
		"panic",    // panic log
		"put",      // put method log
		"get",      // get method log
		"download", // download log
		"open",     // open log
		"delete",   // delete log
		"track",    // track log
		"part",     // part storage log
		"full",     // full storage log
		"range",    // range storage log
	}
)

func NewLogs(logfiles map[string]string) (Logger, error) {
	var (
		l       = &logs{}
		logpath = make(map[string]string, 0)
	)
	for name, fpath := range logfiles {
		dir := getFilePath(fpath)
		_, err := os.Stat(dir)
		if err != nil {
			err = os.MkdirAll(dir, 0755)
			if err != nil {
				return nil, errors.Errorf("%v,%v", dir, err)
			}
		}
		Encoder := getEncoder()
		newCore := zapcore.NewTee(
			zapcore.NewCore(Encoder, getWriteSyncer(fpath), zap.NewAtomicLevel()),
		)
		logpath[name] = fpath
		switch name {
		case "log":
			l.log_log = zap.New(newCore, zap.AddCaller())
			l.log_log.Sugar().Infof("%v", fpath)
		case "panic":
			l.log_pnc = zap.New(newCore, zap.AddCaller())
			l.log_pnc.Sugar().Infof("%v", fpath)
		case "put":
			l.log_put = zap.New(newCore, zap.AddCaller())
			l.log_put.Sugar().Infof("%v", fpath)
		case "get":
			l.log_get = zap.New(newCore, zap.AddCaller())
			l.log_get.Sugar().Infof("%v", fpath)
		case "download":
			l.log_down = zap.New(newCore, zap.AddCaller())
			l.log_down.Sugar().Infof("%v", fpath)
		case "open":
			l.log_open = zap.New(newCore, zap.AddCaller())
			l.log_open.Sugar().Infof("%v", fpath)
		case "delete":
			l.log_del = zap.New(newCore, zap.AddCaller())
			l.log_del.Sugar().Infof("%v", fpath)
		case "track":
			l.log_track = zap.New(newCore, zap.AddCaller())
			l.log_track.Sugar().Infof("%v", fpath)
		case "part":
			l.log_part = zap.New(newCore, zap.AddCaller())
			l.log_part.Sugar().Infof("%v", fpath)
		case "full":
			l.log_full = zap.New(newCore, zap.AddCaller())
			l.log_full.Sugar().Infof("%v", fpath)
		case "range":
			l.log_range = zap.New(newCore, zap.AddCaller())
			l.log_range.Sugar().Infof("%v", fpath)
		}
	}
	l.logpath = logpath
	return l, nil
}

func (l *logs) Log(level string, msg string) {
	_, file, line, _ := runtime.Caller(1)
	switch level {
	case "info":
		l.log_log.Sugar().Infof("[%v:%d] %v", filepath.Base(file), line, msg)
	case "err":
		l.log_log.Sugar().Errorf("[%v:%d] %v", filepath.Base(file), line, msg)
	}

}

func (l *logs) Pnc(msg string) {
	_, file, line, _ := runtime.Caller(1)
	l.log_pnc.Sugar().Errorf("[%s:%d] %s", filepath.Base(file), line, msg)
}

func (l *logs) Logput(level string, msg string) {
	_, file, line, _ := runtime.Caller(1)
	switch level {
	case "info":
		l.log_put.Sugar().Infof("[%v:%d] %s", filepath.Base(file), line, msg)
	case "err":
		l.log_put.Sugar().Errorf("[%v:%d] %s", filepath.Base(file), line, msg)
	}
}

func (l *logs) Logget(level string, msg string) {
	_, file, line, _ := runtime.Caller(1)
	switch level {
	case "info":
		l.log_get.Sugar().Infof("[%v:%d] %v", filepath.Base(file), line, msg)
	case "err":
		l.log_get.Sugar().Errorf("[%v:%d] %v", filepath.Base(file), line, msg)
	}
}

func (l *logs) Logdown(level string, msg string) {
	_, file, line, _ := runtime.Caller(1)
	switch level {
	case "info":
		l.log_down.Sugar().Infof("[%v:%d] %v", filepath.Base(file), line, msg)
	case "err":
		l.log_down.Sugar().Errorf("[%v:%d] %v", filepath.Base(file), line, msg)
	}
}

func (l *logs) Logopen(level string, msg string) {
	_, file, line, _ := runtime.Caller(1)
	switch level {
	case "info":
		l.log_open.Sugar().Infof("[%v:%d] %v", filepath.Base(file), line, msg)
	case "err":
		l.log_open.Sugar().Errorf("[%v:%d] %v", filepath.Base(file), line, msg)
	}
}

func (l *logs) Logdel(level string, msg string) {
	_, file, line, _ := runtime.Caller(1)
	switch level {
	case "info":
		l.log_del.Sugar().Infof("[%v:%d] %v", filepath.Base(file), line, msg)
	case "err":
		l.log_del.Sugar().Errorf("[%v:%d] %v", filepath.Base(file), line, msg)
	}
}

func (l *logs) Logtrack(level string, msg string) {
	_, file, line, _ := runtime.Caller(1)
	switch level {
	case "info":
		l.log_track.Sugar().Infof("[%v:%d] %v", filepath.Base(file), line, msg)
	case "err":
		l.log_track.Sugar().Errorf("[%v:%d] %v", filepath.Base(file), line, msg)
	}
}

func (l *logs) Logpart(level string, msg string) {
	_, file, line, _ := runtime.Caller(1)
	switch level {
	case "info":
		l.log_part.Sugar().Infof("[%v:%d] %v", filepath.Base(file), line, msg)
	case "err":
		l.log_part.Sugar().Errorf("[%v:%d] %v", filepath.Base(file), line, msg)
	}
}

func (l *logs) Logfull(level string, msg string) {
	_, file, line, _ := runtime.Caller(1)
	switch level {
	case "info":
		l.log_full.Sugar().Infof("[%v:%d] %v", filepath.Base(file), line, msg)
	case "err":
		l.log_full.Sugar().Errorf("[%v:%d] %v", filepath.Base(file), line, msg)
	}
}

func (l *logs) Logrange(level string, msg string) {
	_, file, line, _ := runtime.Caller(1)
	switch level {
	case "info":
		l.log_range.Sugar().Infof("[%v:%d] %v", filepath.Base(file), line, msg)
	case "err":
		l.log_range.Sugar().Errorf("[%v:%d] %v", filepath.Base(file), line, msg)
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
