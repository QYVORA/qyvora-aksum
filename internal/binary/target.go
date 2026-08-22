// Package binary defines aksum's target model: the structured description
// of a file under analysis plus the security-property view derived from its
// format metadata. Format-specific packages (formats/elf) fill this model;
// nothing may guess values — undeterminable fields stay empty and are
// rendered as "unknown"/"not detected" (spec section 5).
package binary

// Format identifiers. Only formats with a real parser behind them may be
// reported; the architecture keeps room for PE/Mach-O without claiming them.
type Format string

const (
	FormatELF   Format = "ELF"
	FormatPE    Format = "PE"
	FormatMachO Format = "Mach-O"
	FormatRaw   Format = "RAW"
)

// Arch is the CPU architecture string as reported to users.
type Arch string

// Endianness of the target's encoded data.
type Endianness string

const (
	Little Endianness = "Little"
	Big    Endianness = "Big"
)

// Tri-state used for security properties where a binary can affirmatively
// have, lack, or not-express a property.
type Property int

const (
	PropertyUnknown Property = iota // not determinable from the file
	PropertyEnabled                 // property present/enabled
	PropertyDisabled                // property demonstrably absent/disabled
)

func (p Property) String() string {
	switch p {
	case PropertyEnabled:
		return "enabled"
	case PropertyDisabled:
		return "disabled"
	default:
		return "unknown"
	}
}

// Linking describes how the binary binds its code.
type Linking string

const (
	Dynamic        Linking = "dynamic"
	Static         Linking = "static"
	UnknownLinking Linking = "unknown"
)

// Target is the structured binary model every later stage consumes.
type Target struct {
	Path       string     `json:"path"`
	Size       int64      `json:"size_bytes"`
	SHA256     string     `json:"sha256"`
	Format     Format     `json:"format"`
	Class      string     `json:"class"` // e.g. ELF64 / ELF32
	Arch       Arch       `json:"arch"`
	Endianness Endianness `json:"endianness"`
	OSType     string     `json:"os"` // ABI/OS tag when expressed (e.g. SYSV, Linux)
	Entry      uint64     `json:"entry_point"`

	Type          string   `json:"type"` // EXEC/DYN/REL/CORE
	PIE           Property `json:"pie"`
	NX            Property `json:"nx"`
	RELRO         string   `json:"relro"` // none | partial | full | unknown
	Canary        Property `json:"canary"`
	Fortify       Property `json:"fortify"`
	Stripped      Property `json:"stripped"`
	DebugInfo     Property `json:"debug_info"`
	Linking       Linking  `json:"linking"`
	Interpreter   string   `json:"interpreter,omitempty"`
	Needed        []string `json:"needed_libraries,omitempty"`
	BuildID       string   `json:"build_id,omitempty"`
	CompilerHints []string `json:"compiler_hints,omitempty"`
}
