// session.go holds the interactive console's analysis session: the loaded
// target, its cached analysis context, and derived results. State is
// initialized when a target is opened and reused by every command so the
// same binary is never re-parsed unnecessarily; results that require
// computation not yet performed are computed on demand and cached.
package console

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/QYVORA/qyvora-aksum/internal/binary"
	"github.com/QYVORA/qyvora-aksum/internal/engine"
	"github.com/QYVORA/qyvora-aksum/internal/loader"
	"github.com/QYVORA/qyvora-aksum/internal/surface"
)

// Session is the per-console analysis state.
type Session struct {
	Target *binary.Target // identified target (any supported format)

	ctx      *engine.Context    // full code-analysis context (ELF only)
	codeNote string             // why code analysis is unavailable, if so
	report   *engine.AnalyzeReport
	surface  *surface.Report
}

// OpenTarget identifies path, makes it the session target, and eagerly
// initializes the analysis context. Identification failures return an
// error; unsupported code analysis degrades to structural-only mode with
// an explanatory note instead of failing the open.
func (s *Session) OpenTarget(path string) error {
	path = expandHome(path)
	t, err := loader.Open(path)
	if err != nil {
		return err
	}
	s.Close()
	s.Target = t
	// Initialize the shared analysis context now so later commands reuse
	// it. Architectures without a decoder keep the target usable for
	// structural commands — aksum reports the limitation honestly.
	ac, aerr := engine.OpenAnalysis(t.Path)
	if aerr != nil {
		var ue *engine.UnsupportedError
		if asUnsupported(aerr, &ue) {
			s.codeNote = ue.Msg
		} else if t.Format == binary.FormatELF {
			return fmt.Errorf("analysis init failed: %w", aerr)
		}
		return nil
	}
	s.ctx = ac
	return nil
}

// Close releases session resources.
func (s *Session) Close() {
	if s.ctx != nil {
		_ = s.ctx.Close()
		s.ctx = nil
	}
	s.Target = nil
	s.report = nil
	s.surface = nil
	s.codeNote = ""
}

// Context returns the cached analysis context or nil when the target does
// not support code/structural analysis.
func (s *Session) Context() (*engine.Context, error) {
	if s.ctx != nil {
		return s.ctx, nil
	}
	if s.codeNote != "" {
		return nil, fmt.Errorf("%s", s.codeNote)
	}
	if s.Target == nil {
		return nil, errNoTarget
	}
	return nil, fmt.Errorf("structural analysis requires an ELF image; %q is %s",
		filepath.Base(s.Target.Path), s.Target.Format)
}

func (s *Session) setReport(r *engine.AnalyzeReport) { s.report = r }

// Report returns the stored analyze report, running the pipeline first
// when no analysis has happened yet in this session.
func (s *Session) Report() (*engine.AnalyzeReport, error) {
	if s.report != nil {
		return s.report, nil
	}
	ac, err := s.Context()
	if err != nil {
		return nil, err
	}
	rep, err := engine.RunPipeline(ac, engine.PipelineOptions{}, nil)
	if err != nil {
		return nil, err
	}
	s.setReport(rep)
	return rep, nil
}

// Surface computes (once) and returns the attack-surface report.
func (s *Session) Surface() (*surface.Report, error) {
	if s.surface != nil {
		return s.surface, nil
	}
	ac, err := s.Context()
	if err != nil {
		return nil, err
	}
	rep := surface.Build(ac.Im.Target, ac.Im, ac.Im.Exports(), ac.ClassifiedStrings())
	s.surface = rep
	return rep, nil
}

// PromptName is the short label shown in the contextual prompt.
func (s *Session) PromptName() string {
	if s.Target == nil {
		return ""
	}
	return filepath.Base(s.Target.Path)
}

// expandHome resolves a leading ~/ to the user's home directory so
// `open ~/samples/app` works as expected.
func expandHome(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			if path == "~" {
				return home
			}
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

func asUnsupported(err error, target **engine.UnsupportedError) bool {
	if ue, ok := err.(*engine.UnsupportedError); ok {
		*target = ue
		return true
	}
	return false
}
