package output

import (
	"bytes"
	"strings"
	"testing"
)

func TestPrintMachineFormats(t *testing.T) {
	v := map[string]any{"framework": "aksum", "count": 2}
	cases := []struct {
		format string
		want   string
	}{
		{"json", `"framework": "aksum"`},
		{"yaml", "framework: aksum"},
		{"markdown", "```json"},
		{"html", "<pre>"},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			var buf bytes.Buffer
			p := New()
			p.SetOutput(&buf)
			p.SetFormat(tc.format)
			if err := p.Print(v); err != nil {
				t.Fatalf("Print: %v", err)
			}
			if !strings.Contains(buf.String(), tc.want) {
				t.Errorf("%s output = %q, want %q", tc.format, buf.String(), tc.want)
			}
		})
	}
}

func TestValidFormat(t *testing.T) {
	for _, f := range []string{"", "terminal", "json", "yaml", "markdown", "html"} {
		if !ValidFormat(f) {
			t.Errorf("ValidFormat(%q) = false", f)
		}
	}
	if ValidFormat("xml") {
		t.Error("ValidFormat(xml) = true")
	}
}
