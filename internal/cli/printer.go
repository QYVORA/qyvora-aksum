package cli

import (
	"os"

	"github.com/QYVORA/qyvora-aksum/internal/output"
)

// outputPrinter aliases the shared printer so command files stay readable.
type outputPrinter = output.Printer

func newOutputPrinter() *outputPrinter { return output.New() }

// eventsWriter resolves the --events flag to a stream destination.
// "stdout"/"stderr" select those streams; anything else is a file path
// created with restrictive permissions (analysis targets are untrusted;
// never world-writable logs).
func eventsWriter() (*os.File, func() error, bool) {
	switch eventsFlag {
	case "", "stdout":
		return nil, nil, false
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
