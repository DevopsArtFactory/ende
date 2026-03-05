package diag

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

var enabled atomic.Bool

func init() {
	enabled.Store(parseEnv(os.Getenv("ENDE_DEBUG")))
}

func parseEnv(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "y", "on", "debug":
		return true
	default:
		return false
	}
}

func SetEnabled(v bool) {
	enabled.Store(v)
}

func Enabled() bool {
	return enabled.Load()
}

func Debugf(format string, args ...any) {
	if !Enabled() {
		return
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	fmt.Fprintf(os.Stderr, "[ende-debug] %s %s\n", ts, fmt.Sprintf(format, args...))
}
