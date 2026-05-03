package output

import (
	"encoding/json"
	"io"
	"time"

	"github.com/tristanvaquero/escape/pkg/check"
)

// Report is the top-level JSON document emitted by --output=json.
// The structure is intentionally simple and stable; downstream tools
// (CI gates, SIEMs, audit trails) can rely on it.
type Report struct {
	Tool        string         `json:"tool"`
	Version     string         `json:"version"`
	GeneratedAt time.Time      `json:"generated_at"`
	Summary     Summary        `json:"summary"`
	Results     []check.Result `json:"results"`
}

// WriteJSON serialises the results as indented JSON.
func WriteJSON(w io.Writer, results []check.Result, version string) error {
	rep := Report{
		Tool:        "escape",
		Version:     version,
		GeneratedAt: time.Now().UTC(),
		Summary:     summarize(results),
		Results:     results,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}
