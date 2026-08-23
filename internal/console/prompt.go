// prompt.go builds the console prompt. The prompt stays visually clean:
// a stable identity prefix plus an optional contextual target label —
// never timestamps, colors, or status noise.
package console

import "fmt"

const (
	basePrompt    = "aksum > "
	promptFmt     = "aksum [%s] > "
	interruptMark = "^C"
)

// Prompt returns the prompt string for the session's current state:
//
//	aksum >
//	aksum [sample] >
func (c *Console) Prompt() string {
	if name := c.sess.PromptName(); name != "" {
		return fmt.Sprintf(promptFmt, name)
	}
	return basePrompt
}
