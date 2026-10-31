package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestCapabilitiesMachineFormats(t *testing.T) {
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
			root := newRootCmd()
			formatFlag = tc.format
			t.Cleanup(func() { formatFlag = "" })
			var buf bytes.Buffer
			root.SetOut(&buf)
			root.SetArgs([]string{"capabilities"})
			if err := root.Execute(); err != nil {
				t.Fatalf("capabilities -o %s: %v", tc.format, err)
			}
			if !strings.Contains(buf.String(), tc.want) {
				t.Errorf("output = %q, want %q", buf.String(), tc.want)
			}
			if tc.format == "json" {
				var doc struct {
					OutputFormats []string `json:"output_formats"`
				}
				if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
					t.Fatalf("invalid JSON: %v", err)
				}
				if len(doc.OutputFormats) != 5 {
					t.Errorf("output_formats = %v", doc.OutputFormats)
				}
			}
		})
	}
}
