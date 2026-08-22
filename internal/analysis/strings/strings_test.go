package strings_test

import (
	"testing"

	strscan "github.com/QYVORA/qyvora-aksum/internal/analysis/strings"
)

func TestExtractRawScansWholeFile(t *testing.T) {
	data := []byte("AB\x00\x00https://qyvora.example/path\x00short")
	got := strscan.ExtractRaw(data, strscan.Options{})
	if len(got) == 0 {
		t.Fatal("expected strings from raw scan")
	}
	for _, s := range got {
		if s.Section != "<raw>" {
			t.Fatalf("section = %q, want <raw>", s.Section)
		}
	}
	if !containsValue(t, got, "https://qyvora.example/path") {
		t.Fatal("URL string missing from raw scan")
	}
	short := strscan.ExtractRaw([]byte("abc"), strscan.Options{}) // below min length
	if len(short) != 0 {
		t.Fatalf("expected no output for short input, got %d", len(short))
	}
}

func containsValue(t *testing.T, strs []strscan.Str, want string) bool {
	t.Helper()
	for _, s := range strs {
		if s.Value == want {
			return true
		}
	}
	return false
}
