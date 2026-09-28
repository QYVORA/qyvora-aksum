package cli

import (
	"os"
	"strings"
)

// eventsWriter resolves the --events flag to a stream destination.
//
//	""  and the disable words below   no event stream
//	"stdout" / "stderr"                that stream
//	anything else                      a file path
//
// The disable words are matched case-insensitively. Without them,
// "--events off" fell through to the file branch and created a file
// literally named "off" in the working directory, so the documented way
// to turn the stream off silently created a file instead.
//
// A file destination is truncated rather than appended, so one file holds
// exactly one run's events. Appending leaves no run boundary in the file,
// which matters to anything tailing it.
func eventsWriter() (*os.File, func() error, bool) {
	if eventsDisabled(eventsFlag) {
		return nil, nil, false
	}
	switch strings.ToLower(eventsFlag) {
	case "stdout":
		return os.Stdout, func() error { return nil }, true
	case "stderr":
		return os.Stderr, func() error { return nil }, true
	default:
		f, err := os.OpenFile(eventsFlag, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return nil, nil, false
		}
		return f, f.Close, true
	}
}

// eventsDisabled reports whether a --events value asks for no stream at all.
//
// The interactive guard and the event plumbing both need this answer, so the
// words live here once. A word that turns the stream off must not read as a
// request to send it somewhere: `tool --events off` opens the session happily,
// because there is nothing to contradict.
func eventsDisabled(spec string) bool {
	switch strings.ToLower(spec) {
	case "", "off", "none", "disable", "disabled":
		return true
	}
	return false
}
