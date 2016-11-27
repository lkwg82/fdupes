package lib

import "log"

type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO = iota
	WARN = iota
	ERROR = iota
	FATAL = iota
	FORMAT = "%-7s "
)

type Log struct {
	level    LogLevel
	MESSAGES map[int]string
}

func NewLog() *Log {
	MESSAGES := map[int]string{
		0: "DEBUG",
		1: "INFO",
		2: "WARN",
		3: "ERROR",
		4: "FATAL",
	}
	return &Log{
		level:INFO,
		MESSAGES:MESSAGES,
	}
}

func (l *Log) SetLevel(level LogLevel) {
	l.level = level
}

func (l *Log) log(level LogLevel, format string, a ...interface{}) {
	if l.level <= level {
		args := make([]interface{}, 0)
		args = append(args, l.MESSAGES[int(level)])
		if a != nil {
			for _, value := range a {
				args = append(args, value)
			}
		}
		log.Printf(FORMAT + format, args...)
	}
}
func (l *Log) Fatal(format string, a ...interface{}) {
	l.log(FATAL, format, a...)
}
func (l *Log) Error(format string, a ...interface{}) {
	l.log(ERROR, format, a...)
}
func (l *Log) Warn(format string, a ...interface{}) {
	l.log(WARN, format, a...)
}
func (l *Log) Info(format string, a ...interface{}) {
	l.log(INFO, format, a...)
}
func (l *Log) Debug(format string, a ...interface{}) {
	l.log(DEBUG, format, a...)
}
