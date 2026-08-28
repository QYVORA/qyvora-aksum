package console

const (
	basePrompt    = "aksum > "
	interruptMark = "^C"
)

// Prompt returns the styled prompt string for the session's current state.
func (c *Console) Prompt() string {
	name := ""
	if c.sess != nil {
		name = c.sess.PromptName()
	}
	return c.ui.Prompt("aksum", name)
}
