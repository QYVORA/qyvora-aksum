// Package exitcode defines the shared QYVORA process exit-code contract.
//
//	0  success
//	1  runtime failure (analysis error, I/O error, internal error)
//	2  usage error (unknown flag/command, invalid value, missing target)
//	3  unsupported target (format or architecture Aksum cannot handle)
//	130 interrupted (128 + SIGINT)
//
// Automation must be able to distinguish these without parsing human
// output. Usage errors are never reported as 1; interrupts always flush
// any open event stream before exiting.
package exitcode

const (
	Success     = 0
	Runtime     = 1
	Usage       = 2
	Unsupported = 3
	Interrupted = 130
)
