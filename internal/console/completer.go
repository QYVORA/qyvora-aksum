// completer.go provides tab completion for the interactive console: command
// and alias names on the first word, subcommand words for `help`/`dynamic`,
// and flag names once a command is resolved. Completion is best-effort UI —
// it never executes anything.
package console

import "strings"

// commandCompleter implements readline.AutoCompleter against the live
// command registry so new commands complete automatically.
type commandCompleter struct{ c *Console }

func (c *Console) newCompleter() *commandCompleter { return &commandCompleter{c: c} }

// Do returns completion suffixes for the token ending at pos, following the
// ergochat/readline contract: each returned rune slice is appended after the
// typed prefix, and offset is the length of that prefix.
func (cm *commandCompleter) Do(line []rune, pos int) ([][]rune, int) {
	text := string(line[:pos])
	trailingSpace := strings.HasSuffix(text, " ") || strings.HasSuffix(text, "\t")
	fields := strings.Fields(text)

	partial := ""
	if !trailingSpace && len(fields) > 0 {
		partial = fields[len(fields)-1]
		fields = fields[:len(fields)-1]
	}

	candidates := cm.candidates(fields, partial)
	if len(candidates) == 0 {
		return nil, 0
	}
	offset := len([]rune(partial))
	suffixes := make([][]rune, 0, len(candidates))
	for _, cand := range candidates {
		suffixes = append(suffixes, []rune(cand[len(partial):]))
	}
	return suffixes, offset
}

// candidates lists possible next tokens given the completed words before the
// cursor and the partial word being typed.
func (cm *commandCompleter) candidates(done []string, partial string) []string {
	switch {
	case len(done) == 0:
		return filterPrefix(cm.allNames(), partial)
	case done[0] == "help" || done[0] == "?":
		return filterPrefix(cm.allNames(), partial)
	}
	name := done[0]
	if resolved, ok := cm.c.aliases[name]; ok {
		name = resolved
	}
	cmd, ok := cm.c.cmds[name]
	if !ok || !strings.HasPrefix(partial, "-") {
		return nil // argument values are context-specific; leave them alone
	}
	flags := make([]string, 0, len(cmd.Flags))
	for _, f := range cmd.Flags {
		flag := "--" + f.Name
		if f.Kind == FlagBool {
			flag += "" // switches take no value
		} else {
			flag += "=" // suggest --flag= form so values complete naturally
		}
		flags = append(flags, flag)
	}
	return filterPrefix(flags, partial)
}

// allNames returns every canonical command name followed by aliases,
// sorted by the registry's construction order (canonical first).
func (cm *commandCompleter) allNames() []string {
	names := make([]string, 0, len(cm.c.cmds)+len(cm.c.aliases))
	for _, cmd := range commandTable() {
		names = append(names, cmd.Name)
		names = append(names, cmd.Aliases...)
	}
	return names
}

func filterPrefix(items []string, prefix string) []string {
	var out []string
	for _, it := range items {
		if strings.HasPrefix(it, prefix) {
			out = append(out, it)
		}
	}
	return out
}
