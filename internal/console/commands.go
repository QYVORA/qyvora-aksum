// commands.go defines the console command registry and every command
// implementation. Commands map onto the existing analysis engine — they
// orchestrate session state and shared renderers, never re-implement
// binary-analysis logic.
package console

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/QYVORA/qyvora-aksum/internal/engine"
	"github.com/QYVORA/qyvora-aksum/internal/version"
)

// Command categories in help-display order.
const (
	catCore      = "CORE"
	catTarget    = "TARGET"
	catStructure = "STRUCTURE"
	catAnalysis  = "ANALYSIS"
	catSecurity  = "SECURITY"
	catSystem    = "SYSTEM"
)

var categoryOrder = []string{catCore, catTarget, catStructure, catAnalysis, catSecurity, catSystem}

// Command is one console command.
type Command struct {
	Name     string
	Aliases  []string
	Category string
	Summary  string // one-liner shown in the overview help
	Usage    string // argument synopsis, e.g. "open <path>"
	Details  string // long-form help body for `help <command>`
	Flags    []FlagSpec
	Run      func(c *Console, p *Parsed) error
}

// flagSpecs indexes the command's flags by name for the parser.
func (cmd *Command) flagSpecs() map[string]FlagSpec {
	m := make(map[string]FlagSpec, len(cmd.Flags))
	for _, f := range cmd.Flags {
		m[f.Name] = f
	}
	return m
}

func (c *Console) registerCommands() {
	c.cmds = map[string]*Command{}
	c.aliases = map[string]string{}
	for _, cmd := range commandTable() {
		c.cmds[cmd.Name] = cmd
		for _, a := range cmd.Aliases {
			c.aliases[a] = cmd.Name
		}
	}
}

func commandTable() []*Command {
	return []*Command{
		{
			Name: "help", Aliases: []string{"?"}, Category: catCore,
			Summary: "Show command help",
			Usage:   "help [command]",
			Details: `Without arguments, lists every command grouped by category.
With a command name (or alias), shows its usage, aliases, flags,
and full description.`,
			Run: runHelp,
		},
		{
			Name: "version", Category: catCore,
			Summary: "Show Aksum version",
			Usage:   "version",
			Details: "Prints the running Aksum version and build identity.",
			Run: func(c *Console, _ *Parsed) error {
				c.printf("aksum %s\n  Commit:    %s\n  Built:     %s\n  BuildUser: %s\n",
					version.Version, version.Commit, version.Date, version.BuildUser)
				return nil
			},
		},
		{
			Name: "status", Category: catCore,
			Summary: "Show current analysis session",
			Usage:   "status",
			Details: "Summarizes the loaded target and everything cached in this session.",
			Flags:   []FlagSpec{{Name: "json", Kind: FlagBool}},
			Run:     runStatus,
		},
		{
			Name: "clear", Category: catCore,
			Summary: "Clear terminal",
			Usage:   "clear",
			Details: "Clears the terminal screen.",
			Run: func(c *Console, _ *Parsed) error {
				c.printf("\033[H\033[2J")
				return nil
			},
		},
		{
			Name: "history", Category: catCore,
			Summary: "Show command history",
			Usage:   "history",
			Details: "Lists the commands executed in this session, oldest first.",
			Run: func(c *Console, _ *Parsed) error {
				lines := c.hist.Lines()
				if len(lines) == 0 {
					c.warnf("history is empty")
					return nil
				}
				for i, l := range lines {
					c.printf("%4d  %s\n", i+1, l)
				}
				return nil
			},
		},
		{
			Name: "quit", Aliases: []string{"exit", "q"}, Category: catCore,
			Summary: "Exit Aksum",
			Usage:   "quit | exit",
			Details: "Leaves the console cleanly (Ctrl+D does the same).",
			Run: func(*Console, *Parsed) error { return errExit },
		},

		{
			Name: "open", Category: catTarget,
			Summary: "Load a binary",
			Usage:   "open <path>",
			Details: `Identifies the file and makes it the session target. The prompt
gains the target name; subsequent commands reuse the cached
analysis context instead of re-reading the file.`,
			Run: runOpen,
		},
		{
			Name: "close", Category: catTarget,
			Summary: "Unload the current target",
			Usage:   "close",
			Details: "Releases the loaded target and all cached analysis state.",
			Run: func(c *Console, _ *Parsed) error {
				if c.sess.Target == nil {
					c.warnf("no target loaded")
					return nil
				}
				c.sess.Close()
				c.ok("Target closed")
				return nil
			},
		},
		{
			Name: "target", Category: catTarget,
			Summary: "Show loaded target",
			Usage:   "target",
			Details: "Prints the identity of the currently loaded target.",
			Flags:   []FlagSpec{{Name: "json", Kind: FlagBool}},
			Run:     runTarget,
		},
		{
			Name: "binary", Aliases: []string{"b"}, Category: catTarget,
			Summary: "Show binary properties",
			Usage:   "binary",
			Details: `Full identification of the loaded binary: format, architecture,
linking, PIE/NX/RELRO/canary/fortify. Undeterminable values are
reported as unknown — never guessed.`,
			Flags: []FlagSpec{{Name: "json", Kind: FlagBool}},
			Run:   runBinary,
		},

		{
			Name: "sections", Aliases: []string{"s"}, Category: catStructure,
			Summary: "List sections",
			Usage:   "sections",
			Details: "Enumerates ELF sections with addresses, sizes, and permissions.",
			Flags:   []FlagSpec{{Name: "json", Kind: FlagBool}},
			Run:     runSections,
		},
		{
			Name: "segments", Aliases: []string{"seg"}, Category: catStructure,
			Summary: "List segments",
			Usage:   "segments",
			Details: "Enumerates program headers with rwx permissions and sizes.",
			Flags:   []FlagSpec{{Name: "json", Kind: FlagBool}},
			Run:     runSegments,
		},
		{
			Name: "symbols", Aliases: []string{"syms"}, Category: catStructure,
			Summary: "List symbols",
			Usage:   "symbols [--dynamic]",
			Details: `Lists symbol-table entries. Stripped binaries have no static
table; --dynamic lists .dynsym entries instead.`,
			Flags: []FlagSpec{
				{Name: "dynamic", Kind: FlagBool},
				{Name: "json", Kind: FlagBool},
			},
			Run: runSymbols,
		},
		{
			Name: "imports", Aliases: []string{"imp"}, Category: catStructure,
			Summary: "List imports",
			Usage:   "imports",
			Details: `Lists imported functions grouped by security relevance.
Categorization is an observation of capability surface — never a
vulnerability claim on its own.`,
			Flags: []FlagSpec{{Name: "json", Kind: FlagBool}},
			Run:   runImports,
		},

		{
			Name: "strings", Aliases: []string{"str"}, Category: catAnalysis,
			Summary: "Extract and classify strings",
			Usage:   "strings [--min-length n] [--max n] [--utf16]",
			Details: `Extracts printable strings from loadable sections and classifies
security-relevant ones (URLs, paths, commands, credentials, crypto).
RAW/unidentified files degrade to whole-file scanning.`,
			Flags: []FlagSpec{
				{Name: "min-length", Kind: FlagInt},
				{Name: "max", Kind: FlagInt},
				{Name: "utf16", Kind: FlagBool},
				{Name: "json", Kind: FlagBool},
			},
			Run: runStrings,
		},
		{
			Name: "functions", Aliases: []string{"fn"}, Category: catAnalysis,
			Summary: "List discovered functions",
			Usage:   "functions [--min-confidence low|medium|high]",
			Details: `Discovers functions from symbols, the entry point, direct call
targets, and prologue heuristics. Confidence is evidence-backed;
stripped binaries yield fewer high-confidence results by design.`,
			Flags: []FlagSpec{
				{Name: "min-confidence", Kind: FlagString},
				{Name: "json", Kind: FlagBool},
			},
			Run: runFunctions,
		},
		{
			Name: "disasm", Aliases: []string{"dis"}, Category: catAnalysis,
			Summary: "Disassemble code",
			Usage:   "disasm [0xaddr | symbol] [--limit n]",
			Details: `Disassembles the discovered function starting at the given hex
address or matching the given name; without an argument, linearly
decodes the executable region. Requires an x86/x86-64 decoder.`,
			Flags: []FlagSpec{
				{Name: "limit", Kind: FlagInt},
				{Name: "json", Kind: FlagBool},
			},
			Run: runDisasm,
		},
		{
			Name: "xrefs", Aliases: []string{"x"}, Category: catAnalysis,
			Summary: "Show cross references",
			Usage:   "xrefs 0x<addr> | xrefs --string <substr>",
			Details: `Shows cross-references to a code/data address, or to every
extracted data string containing the given substring.`,
			Flags: []FlagSpec{
				{Name: "string", Kind: FlagString},
				{Name: "json", Kind: FlagBool},
			},
			Run: runXrefs,
		},
		{
			Name: "calls", Category: catAnalysis,
			Summary: "Show call relationships",
			Usage:   "calls [--func name]",
			Details: "Shows the direct-call graph between discovered functions.",
			Flags: []FlagSpec{
				{Name: "func", Kind: FlagString},
				{Name: "json", Kind: FlagBool},
			},
			Run: runCalls,
		},
		{
			Name: "cfg", Category: catAnalysis,
			Summary: "Show control-flow information",
			Usage:   "cfg [--func name]",
			Details: "Per-function control-flow metrics: blocks, edges, loops, unreachable blocks.",
			Flags: []FlagSpec{
				{Name: "func", Kind: FlagString},
				{Name: "json", Kind: FlagBool},
			},
			Run: runCfg,
		},

		{
			Name: "surface", Category: catSecurity,
			Summary: "Analyze attack surface",
			Usage:   "surface",
			Details: `Aggregates entry points, security-relevant import categories,
exported functions, and classified string classes into one view.
Every number traces to a concrete observation.`,
			Flags: []FlagSpec{{Name: "json", Kind: FlagBool}},
			Run:   runSurface,
		},
		{
			Name: "analyze", Category: catSecurity,
			Summary: "Run analysis pipeline",
			Usage:   "analyze [--min-severity info|low|medium|high|critical]",
			Details: `Runs identification, strings, function discovery, cross-reference
mapping, dataflow call-site resolution, every static rule, and the
validation pass, then stores deduplicated findings in the session.
Findings are observations, not verdicts.`,
			Flags: []FlagSpec{
				{Name: "min-severity", Kind: FlagString},
				{Name: "json", Kind: FlagBool},
			},
			Run: runAnalyze,
		},
		{
			Name: "findings", Category: catSecurity,
			Summary: "Show findings",
			Usage:   "findings [--details]",
			Details: `Displays the stored analysis findings (running the pipeline first
when needed). Each record states severity, confidence, evidence,
detection reason, and validation guidance.`,
			Flags: []FlagSpec{
				{Name: "details", Kind: FlagBool},
				{Name: "json", Kind: FlagBool},
			},
			Run: runFindings,
		},
		{
			Name: "report", Category: catSecurity,
			Summary: "Write JSON report to file",
			Usage:   "report <path>",
			Details: `Writes the schema-versioned machine-readable analysis report to
<path>. Runs the pipeline first when it has not run yet in this
session.`,
			Run: runReport,
		},
		{
			Name: "dynamic", Category: catSecurity,
			Summary: "Dynamic-analysis planning",
			Usage:   "dynamic plan [--arg a] [--timeout dur] [--allow-network]",
			Details: `Builds an auditable execution plan under a mechanical safety
policy. This build bundles NO sandbox backend: 'plan' validates and
prints what WOULD run; execution is refused — feed the plan to your
own isolation boundary.`,
			Flags: []FlagSpec{
				{Name: "timeout", Kind: FlagString},
				{Name: "allow-network", Kind: FlagBool},
				{Name: "allow-file-write", Kind: FlagBool},
				{Name: "max-output-bytes", Kind: FlagInt},
				{Name: "yes", Kind: FlagBool},
				{Name: "arg", Kind: FlagStringSlice},
			},
			Run: runDynamic,
		},

		{
			Name: "update", Category: catSystem,
			Summary: "Update Aksum",
			Usage:   "update",
			Details: `Checks the running version against official QYVORA GitHub
releases, verifies downloads against the published SHA-256
manifest, and swaps the binary atomically.`,
			Run: runUpdate,
		},
	}
}

// ---- helpers shared by commands ---------------------------------------

// requireContext returns the session's analysis context or prints the
// canonical guidance when no usable target is loaded.
func requireContext(c *Console) (*engine.Context, error) {
	if c.sess.Target == nil {
		c.warnf("No target loaded.")
		c.printf("Use: open <binary>\n")
		return nil, errNoTarget
	}
	ac, err := c.sess.Context()
	if err != nil {
		c.failf("%v", err)
		return nil, err
	}
	return ac, nil
}

// emitJSON writes machine-readable output for one command and reports
// whether it handled the invocation.
func emitJSON(c *Console, p *Parsed, v any) bool {
	if !p.Bool("json") {
		return false
	}
	enc := json.NewEncoder(c.out)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
	return true
}

// parseAddr accepts 0x-prefixed and bare hexadecimal addresses.
func parseAddr(s string) (uint64, error) {
	v, err := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid address %q (hexadecimal)", s)
	}
	return v, nil
}

// suggest returns the closest known command/alias within edit distance 2.
func (c *Console) suggest(word string) string {
	names := make([]string, 0, len(c.cmds)+len(c.aliases))
	for n := range c.cmds {
		names = append(names, n)
	}
	for a := range c.aliases {
		names = append(names, a)
	}
	sort.Strings(names)
	best, bestDist := "", 3
	for _, n := range names {
		if strings.HasPrefix(n, word) && len(word) >= 2 {
			return n // prefix match wins immediately
		}
		d := levenshtein(word, n, bestDist)
		if d < bestDist {
			best, bestDist = n, d
		}
	}
	return best
}

// levenshtein computes edit distance, bailing out once it exceeds cap.
func levenshtein(a, b string, cap int) int {
	ar, br := []rune(a), []rune(b)
	prev := make([]int, len(br)+1)
	cur := make([]int, len(br)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ar); i++ {
		cur[0] = i
		rowMin := cur[0]
		for j := 1; j <= len(br); j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			cur[j] = min3(cur[j-1]+1, prev[j]+1, prev[j-1]+cost)
			if cur[j] < rowMin {
				rowMin = cur[j]
			}
		}
		if rowMin > cap {
			return cap + 1
		}
		copy(prev, cur)
	}
	if prev[len(br)] > cap {
		return cap + 1
	}
	return prev[len(br)]
}

func min3(a, b, c int) int {
	if b < a {
		a = b
	}
	if c < a {
		a = c
	}
	return a
}

var errMinArgs = errors.New("missing argument")

// needArgs enforces positional argument counts with clean messages.
func needArgs(p *Parsed, atLeast int) error {
	if p.ArgsLen() < atLeast {
		return fmt.Errorf("%w: see 'help %s'", errMinArgs, p.Name)
	}
	return nil
}
