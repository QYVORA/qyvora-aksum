package cli

import "os"

// eventsWriter resolves the --events flag to a stream destination.
// "stdout"/"stderr" select those streams; anything else is a file path
// created with restrictive permissions (analysis targets are untrusted;
// never world-writable logs). An empty value selects no event stream.
func eventsWriter() (*os.File, func() error, bool) {
	switch eventsFlag {
	case "":
		return nil, nil, false
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
