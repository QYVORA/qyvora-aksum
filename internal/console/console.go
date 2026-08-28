// Package console implements aksum's interactive console: a persistent
// reverse-engineering session with a contextual prompt, command history,
// typed argument parsing, and tabular result rendering. It reuses the same
// analysis engine as the one-shot CLI — nothing about binary analysis is
// duplicated here.
//
// Launching `aksum` with no subcommand enters this console; every existing
// one-shot command keeps working unchanged.
package console

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/ergochat/readline"
	"golang.org/x/term"

	"github.com/QYVORA/qyvora-aksum/internal/version"
)

// errExit is the internal sentinel returned by exit commands.
var errExit = errors.New("exit")

// errNoTarget is the canonical "nothing loaded" message.
var errNoTarget = errors.New("no target loaded")

// Options configure a console instance.
type Options struct {
	In          io.Reader // input stream (default os.Stdin)
	Out         io.Writer // human output (default os.Stdout)
	Err         io.Writer // error output (default os.Stderr)
	Interactive bool      // TTY mode: line editing, banner, persistent history
	HistoryPath string    // history file override; "" = default, "off" = none
}

// Console is one interactive aksum session.
type Console struct {
	in          io.Reader
	out         io.Writer
	errW        io.Writer
	interactive bool

	sess    *Session
	hist    *History
	cmds    map[string]*Command
	aliases map[string]string
	lr      lineReader
	ui      *UI

	histPathOverride string

	cancelMu    sync.Mutex
	opCtx       context.Context
	opCancel    context.CancelFunc
	interrupted atomic.Bool
}

// New builds a console from opts.
func New(opts Options) *Console {
	c := &Console{
		in:          opts.In,
		out:         opts.Out,
		errW:        opts.Err,
		interactive: opts.Interactive,
		sess:        &Session{},
		hist:        NewHistory(),
	}
	if c.in == nil {
		c.in = os.Stdin
	}
	if c.out == nil {
		c.out = os.Stdout
	}
	if c.errW == nil {
		c.errW = os.Stderr
	}
	c.ui = newUI(c.out)
	c.registerCommands()
	return c
}

// Run drives the read-eval loop until exit/quit/Ctrl+D. It returns a
// process exit code.
func (c *Console) Run(rootCtx context.Context) int {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)
	go func() {
		for range sigCh {
			c.interrupted.Store(true)
			c.cancelOperation()
		}
	}()

	var lr lineReader = newPipeReader(c.in)
	if c.interactive && term.IsTerminal(int(os.Stdin.Fd())) {
		if instance, err := c.newReadline(); err == nil {
			lr = &readlineReader{rl: instance}
			defer instance.Close() //nolint:errcheck // terminal restore best-effort
		}
	}
	c.lr = lr

	if c.interactive {
		c.printBanner()
		c.hud()
		c.ui.Status("*", "console ready. type 'help' for commands.")
	}

	for {
		line, rerr := lr.Read(c.Prompt())
		switch {
		case errors.Is(rerr, io.EOF):
			if c.interactive {
				fmt.Fprintln(c.out)
			}
			c.sess.Close()
			return 0
		case errors.Is(rerr, readline.ErrInterrupt):
			// Ctrl+C aborts the current input line, never the session.
			fmt.Fprintln(c.out, interruptMark)
			continue
		case rerr != nil:
			c.sess.Close()
			return 0
		}

		if c.execute(rootCtx, line) {
			c.sess.Close()
			return 0
		}
		if c.interactive {
			c.hud()
		}
		c.interrupted.Store(false)
	}
}

// newReadline builds the TTY line editor with persistent history.
func (c *Console) newReadline() (*readline.Instance, error) {
	cfg := &readline.Config{
		Prompt:          basePrompt,
		InterruptPrompt: interruptMark,
		EOFPrompt:       "exit",
		HistoryLimit:    historyLimit,
		AutoComplete:    c.newCompleter(),
	}
	if c.interactive {
		switch path := c.historyPath(); {
		case path != "":
			cfg.HistoryFile = path
		}
	}
	return readline.NewEx(cfg)
}

func (c *Console) historyPath() string {
	if !c.interactive {
		return ""
	}
	if c.histPathOverride == "off" {
		return ""
	}
	if c.histPathOverride != "" {
		return c.histPathOverride
	}
	return DefaultHistoryPath()
}

// execute parses and dispatches one input line under a cancellable operation
// context. It returns true when the session should end.
func (c *Console) execute(rootCtx context.Context, line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return false // blank or comment line
	}
	c.hist.Add(trimmed)

	opCtx, cancel := context.WithCancel(rootCtx)
	defer cancel()
	c.setOpCancel(opCtx, cancel)

	toks, terr := tokenize(trimmed)
	if terr != nil {
		c.failf("%v", terr)
		return false
	}

	word := strings.ToLower(toks[0])
	name := word
	if resolved, ok := c.aliases[word]; ok {
		name = resolved
	}
	cmd, ok := c.cmds[name]
	if !ok {
		c.failf("Unknown command: %s", word)
		if hint := c.suggest(word); hint != "" {
			fmt.Fprintf(c.errW, "Did you mean '%s'?\n", hint)
		}
		fmt.Fprintln(c.errW, "Try 'help'.")
		return false
	}

	parsed, perr := parse(name, trimmed, toks[1:], cmd.flagSpecs())
	if perr != nil {
		c.failf("%v", perr)
		return false
	}

	if err := cmd.Run(c, parsed); err != nil {
		if errors.Is(err, errExit) {
			return true
		}
		c.failf("%v", err)
	}
	return false
}

// ---- output helpers -------------------------------------------------

// printf writes to the human output stream.
func (c *Console) printf(format string, a ...any) {
	fmt.Fprintf(c.out, format, a...)
}

// phase prints a phase header line: [ANALYSIS] Functions discovered: 42.
func (c *Console) phase(phaseName, format string, a ...any) {
	fmt.Fprintf(c.out, "[%s] %s\n", phaseName, fmt.Sprintf(format, a...))
}

// ok prints a [+]-prefixed confirmation.
func (c *Console) ok(format string, a ...any) {
	fmt.Fprintf(c.out, "[+] %s\n", fmt.Sprintf(format, a...))
}

// failf prints a [!]-prefixed error to stderr without killing the session.
func (c *Console) failf(format string, a ...any) {
	fmt.Fprintf(c.errW, "[!] %s\n", fmt.Sprintf(format, a...))
}

// warnf prints a [!]-prefixed warning to the output stream.
func (c *Console) warnf(format string, a ...any) {
	fmt.Fprintf(c.out, "[!] %s\n", fmt.Sprintf(format, a...))
}

// OpContext returns the currently executing command's context; it is
// canceled by the next Ctrl+C so long operations can stop cleanly.
func (c *Console) OpContext() context.Context {
	c.cancelMu.Lock()
	defer c.cancelMu.Unlock()
	if c.opCtx != nil {
		return c.opCtx
	}
	return context.Background()
}

func (c *Console) setOpCancel(ctx context.Context, cancel context.CancelFunc) {
	c.cancelMu.Lock()
	c.opCtx = ctx
	c.opCancel = cancel
	c.cancelMu.Unlock()
}

func (c *Console) cancelOperation() {
	c.cancelMu.Lock()
	if c.opCancel != nil {
		c.opCancel()
	}
	c.cancelMu.Unlock()
}

func (c *Console) hud() {
	if !c.interactive {
		return
	}
	target := "none"
	arch := "none"
	if c.sess.Target != nil {
		target = c.sess.PromptName()
		if c.sess.Target.Arch != "" {
			arch = string(c.sess.Target.Arch)
		}
	}
	cwd, _ := os.Getwd()
	v := version.Version
	if v == "" {
		v = "dev"
	}
	c.ui.HUD(target, arch, cwd, v)
}

// printBanner writes the canonical startup banner.
func (c *Console) printBanner() {
	v := version.Version
	if v == "" {
		v = "dev"
	}
	c.ui.Banner("Binary Security & Reverse Engineering Platform")
	c.ui.BannerFoot(v)
}

// ---- line readers ----------------------------------------------------

// lineReader abstracts interactive vs piped input so tests never depend on
// a user's terminal.
type lineReader interface {
	Read(prompt string) (string, error)
	Close() error
}

// readlineReader wraps an ergochat/readline instance for TTY sessions:
// arrow-key history, backspace editing, Ctrl+C line abort, Ctrl+D EOF.
type readlineReader struct{ rl *readline.Instance }

func (r *readlineReader) Read(prompt string) (string, error) {
	r.rl.SetPrompt(prompt)
	return r.rl.Readline()
}

func (r *readlineReader) Close() error { return r.rl.Close() }

// pipeReader reads lines from any stream (scripts, tests). Prompts are not
// echoed so redirected output stays clean.
type pipeReader struct {
	scanner *bufio.Scanner
}

func newPipeReader(in io.Reader) *pipeReader {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	return &pipeReader{scanner: sc}
}

func (p *pipeReader) Read(_ string) (string, error) {
	if !p.scanner.Scan() {
		return "", io.EOF
	}
	return p.scanner.Text(), nil
}

func (p *pipeReader) Close() error { return nil }
