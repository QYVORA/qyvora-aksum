package table

import (
	"os"

	"golang.org/x/term"
)

// probeTermWidth asks the OS for the terminal size of stdout, falling back
// to stderr/stdin when stdout is redirected (tables still render against a
// sane budget), then DefaultWidth.
func probeTermWidth() int {
	for _, f := range []*os.File{os.Stdout, os.Stderr, os.Stdin} {
		if w, _, err := term.GetSize(int(f.Fd())); err == nil && w >= MinTableWidth {
			return w
		}
	}
	return DefaultWidth
}
