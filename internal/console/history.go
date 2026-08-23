// history.go records console command history for the `history` command.
// Interactive sessions additionally persist cross-session history through
// the line editor's history file; this structure stays in-memory by design
// so scripted sessions remain side-effect free.
package console

import (
	"os"
	"path/filepath"
	"strings"
)

// historyLimit caps recorded entries (also used as the editor history cap).
const historyLimit = 1000

const historyFileName = ".aksum_history"

// History stores executed command lines in order.
type History struct {
	lines []string
}

// NewHistory returns an empty in-memory history.
func NewHistory() *History { return &History{} }

// DefaultHistoryPath returns the conventional cross-session history file,
// or "" when no home directory is available.
func DefaultHistoryPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, historyFileName)
}

// Add records one executed command line, deduplicating consecutive repeats.
func (h *History) Add(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	if n := len(h.lines); n > 0 && h.lines[n-1] == line {
		return
	}
	h.lines = append(h.lines, line)
	if len(h.lines) > historyLimit {
		h.lines = h.lines[len(h.lines)-historyLimit:]
	}
}

// Lines returns the recorded lines.
func (h *History) Lines() []string {
	out := make([]string, len(h.lines))
	copy(out, h.lines)
	return out
}

// Len returns the number of recorded lines.
func (h *History) Len() int { return len(h.lines) }
