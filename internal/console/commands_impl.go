// commands_impl.go holds the console command implementations, part 1:
// help/status/session/target commands plus shared text helpers. Each runner
// composes session state, the analysis engine, and shared renderers.
package console

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/QYVORA/qyvora-aksum/internal/binary"
	"github.com/QYVORA/qyvora-aksum/internal/engine"
)

// runHelp implements `help`, `?`, and `help <command>`.
func runHelp(c *Console, p *Parsed) error {
	if p.ArgsLen() > 0 {
		return helpCommand(c, p.Arg(0))
	}
	for _, cat := range categoryOrder {
		cmds := commandsInCategory(cat)
		if len(cmds) == 0 {
			continue
		}
		c.ui.Section(cat + " Commands")
		var rows [][]string
		for _, cmd := range cmds {
			rows = append(rows, []string{cmd.displayUsage(), cmd.Summary})
		}
		c.ui.Table([]string{"COMMAND", "DESCRIPTION"}, rows)
	}
	c.ui.Section("Guidance")
	c.printf("  Aliases: %s\n", aliasSummary())
	c.printf("  Use 'help <command>' for details; append --json for machine-readable output.\n")
	c.ui.Rule()
	return nil
}

func helpCommand(c *Console, word string) error {
	name := strings.ToLower(word)
	if resolved, ok := c.aliases[name]; ok {
		name = resolved
	}
	cmd, ok := c.cmds[name]
	if !ok {
		return fmt.Errorf("no such command: %q (try 'help')", word)
	}
	c.printf("\n%s — %s\n", cmd.Name, cmd.Summary)
	c.printf("  usage:   %s\n", cmd.displayUsage())
	if len(cmd.Aliases) > 0 {
		c.printf("  aliases: %s\n", strings.Join(cmd.Aliases, ", "))
	}
	if len(cmd.Flags) > 0 {
		c.printf("  flags:\n")
		for _, f := range cmd.Flags {
			c.printf("    %s\n", f.usage())
		}
	}
	if cmd.Details != "" {
		c.printf("\n%s\n", indentBlock(cmd.Details, "    "))
	}
	return nil
}

func (cmd *Command) displayUsage() string {
	if cmd.Usage != "" {
		return cmd.Usage
	}
	return cmd.Name
}

func commandsInCategory(cat string) []*Command {
	var out []*Command
	for _, cmd := range commandTable() {
		if cmd.Category == cat {
			out = append(out, cmd)
		}
	}
	return out
}

// aliasSummary renders "exit/q -> quit, ? -> help, ..." for overview help.
func aliasSummary() string {
	canonicals := []string{"quit", "help", "binary", "sections", "segments",
		"symbols", "imports", "strings", "functions", "disasm", "xrefs"}
	var pairs []string
	for _, name := range canonicals {
		cmd, ok := c_lookup(name)
		if ok && len(cmd.Aliases) > 0 {
			pairs = append(pairs, fmt.Sprintf("%s -> %s", strings.Join(cmd.Aliases, "/"), name))
		}
	}
	return strings.Join(pairs, ", ")
}

// c_lookup resolves a canonical command name from the static table.
func c_lookup(name string) (*Command, bool) {
	for _, cmd := range commandTable() {
		if cmd.Name == name {
			return cmd, true
		}
	}
	return nil, false
}

// indentBlock re-indents multi-line detail text uniformly.
func indentBlock(s, pad string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = pad + l
	}
	return strings.Join(lines, "\n")
}

// runOpen loads a target and initializes the session's analysis context.
func runOpen(c *Console, p *Parsed) error {
	if err := needArgs(p, 1); err != nil {
		return err
	}
	path := expandHome(p.Arg(0))
	st, serr := os.Stat(path)
	if serr != nil {
		return fmt.Errorf("failed to open target: file does not exist")
	}
	if st.IsDir() {
		return fmt.Errorf("failed to open target: %s is a directory", path)
	}
	if err := c.sess.OpenTarget(path); err != nil {
		return fmt.Errorf("failed to open target: %w", err)
	}
	t := c.sess.Target
	c.ok("Target loaded")
	c.printf("  File          %s\n", baseName(t.Path))
	format := string(t.Format)
	if t.Format != binary.FormatRaw && t.Class != "" {
		format = fmt.Sprintf("%s (%s/%s)", t.Format, t.Class, t.Type)
	}
	c.printf("  Format        %s\n", format)
	if t.Format != binary.FormatRaw {
		c.printf("  Architecture  %s\n", t.Arch)
		c.printf("  Entry         %s\n", engine.Addr(t.Entry))
	}
	if c.sess.codeNote != "" {
		c.warnf("%s", c.sess.codeNote)
	}
	return nil
}

func baseName(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[i+1:]
	}
	return path
}

// runStatus summarizes everything cached in this session.
func runStatus(c *Console, p *Parsed) error {
	t := c.sess.Target
	rows := [][2]string{
		{"Target", "-"},
		{"Code analysis", "-"},
		{"Functions discovered", "-"},
		{"Findings stored", "-"},
		{"History entries", strconv.Itoa(c.hist.Len())},
	}
	if t != nil {
		rows[0] = [2]string{"Target", fmt.Sprintf("%s (%s/%s)",
			baseName(t.Path), t.Format, t.Arch)}
		if ac, aerr := c.sess.Context(); aerr == nil {
			rows[1] = [2]string{"Code analysis", "ready"}
			rows[2] = [2]string{"Functions discovered", strconv.Itoa(len(ac.Funcs))}
		} else if c.sess.codeNote != "" {
			rows[1] = [2]string{"Code analysis", "unavailable"}
		}
		if r := c.sess.report; r != nil {
			rows[3] = [2]string{"Findings stored", strconv.Itoa(len(r.Findings))}
		}
	}
	if p.Bool("json") {
		m := map[string]string{}
		for _, r := range rows {
			m[r[0]] = r[1]
		}
		return json.NewEncoder(c.out).Encode(m)
	}
	c.ok("Session status")
	width := 0
	for _, r := range rows {
		if len(r[0]) > width {
			width = len(r[0])
		}
	}
	for _, r := range rows {
		c.printf("  %-*s  %s\n", width, r[0], r[1])
	}
	return nil
}

// runTarget prints the loaded target identity.
func runTarget(c *Console, p *Parsed) error {
	if c.sess.Target == nil {
		c.warnf("No target loaded.")
		c.printf("Use: open <binary>\n")
		return nil
	}
	t := c.sess.Target
	if emitJSON(c, p, t) {
		return nil
	}
	c.ok("Loaded target")
	rows := [][2]string{
		{"File", baseName(t.Path)},
		{"Path", t.Path},
		{"Format", string(t.Format)},
		{"Size", fmt.Sprintf("%d bytes", t.Size)},
		{"SHA256", t.SHA256},
	}
	if t.Format != binary.FormatRaw {
		rows = append(rows,
			[2]string{"Architecture", string(t.Arch)},
			[2]string{"Entry", engine.Addr(t.Entry)},
		)
	}
	width := 0
	for _, r := range rows {
		if len(r[0]) > width {
			width = len(r[0])
		}
	}
	for _, r := range rows {
		c.printf("  %-*s  %s\n", width, r[0], r[1])
	}
	return nil
}

// runBinary prints full identification properties.
func runBinary(c *Console, p *Parsed) error {
	if c.sess.Target == nil {
		c.warnf("No target loaded.")
		c.printf("Use: open <binary>\n")
		return nil
	}
	if emitJSON(c, p, c.sess.Target) {
		return nil
	}
	engine.RenderTargetProperties(c.out, c.sess.Target)
	return nil
}
