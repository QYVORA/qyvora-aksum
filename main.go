// Command aksum is QYVORA's binary-security assessment engine: reverse
// engineering, binary analysis, and evidence-driven security assessment for
// compiled software.
package main

import (
	"os"

	"github.com/QYVORA/qyvora-aksum/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
