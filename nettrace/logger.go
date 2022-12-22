package nettrace

import "github.com/sirupsen/logrus"

// sirupsenLogger : default logger used to log noteworthy events happening inside
// the network tracing engine.
type sirupsenLogger struct {
	logger *logrus.Logger
}

func newSirupsenLogger() *sirupsenLogger {
	return &sirupsenLogger{
		logger: logrus.New(),
	}
}

func (sl *sirupsenLogger) Tracef(format string, args ...interface{}) {
	sl.logger.Tracef(format, args...)
}

func (sl *sirupsenLogger) Noticef(format string, args ...interface{}) {
	sl.logger.Debugf(format, args...)
}

func (sl *sirupsenLogger) Warningf(format string, args ...interface{}) {
	sl.logger.Warningf(format, args...)
}

func (sl *sirupsenLogger) Errorf(format string, args ...interface{}) {
	sl.logger.Errorf(format, args...)
}

func (sl *sirupsenLogger) Fatalf(format string, args ...interface{}) {
	sl.logger.Fatalf(format, args...)
}

func (sl *sirupsenLogger) Panicf(format string, args ...interface{}) {
	sl.logger.Panicf(format, args...)
}

type noopLogger struct{}

func (sl *noopLogger) Tracef(format string, args ...interface{}) {}

func (sl *noopLogger) Noticef(format string, args ...interface{}) {}

func (sl *noopLogger) Warningf(format string, args ...interface{}) {}

func (sl *noopLogger) Errorf(format string, args ...interface{}) {}

func (sl *noopLogger) Fatalf(format string, args ...interface{}) {}

func (sl *noopLogger) Panicf(format string, args ...interface{}) {}
