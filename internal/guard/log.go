package guard

import "log/slog"

// EventLogger adapts library loggers without passing through addresses or data.
type EventLogger struct{ Event string }

func (l EventLogger) Printf(_ string, _ ...interface{}) { slog.Warn(l.Event) }
func (l EventLogger) Println(_ ...interface{})          { slog.Warn(l.Event) }
