package lastpass

import "context"

type key int

const (
	loggerKey key = iota
)

// Logger is the interface which wraps the Printf method.
type Logger interface {
	Printf(format string, v ...interface{})
}

// NewContextWithLogger returns a new context with logging enabled.
func NewContextWithLogger(ctx context.Context, logger Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

func log(ctx context.Context, c *Client, format string, v ...interface{}) {
	if logger, ok := ctx.Value(loggerKey).(Logger); ok {
		logger.Printf(format, v...)
	}
	if c.logger != nil {
		c.logger.Printf(format, v...)
	}
}
