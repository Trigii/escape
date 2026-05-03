package output

import (
	"encoding/json"
	"io"

	"github.com/tristanvaquero/escape/pkg/check"
)

// WriteSARIF emits a SARIF 2.1.0 document compatible with GitHub Code
// Scanning, Azure DevOps, and most CI dashboards. Only failed/errored
// results become "result" entries; passes and skips are dropped because
// SARIF is a finding format.
func WriteSARIF(w io.Writer, results []check.Result, version string) error {
	rules := make([]sarifRule, 0, len(results))
	seen := map[string]bool{}
	var sarifResults []sarifResult

	for _, r := range results {
		if !seen[r.ID] {
			seen[r.ID] = true
			rules = append(rules, sarifRule{
				ID:               r.ID,
				Name:             r.Name,
				ShortDescription: sarifText{Text: r.Name},
				FullDescription:  sarifText{Text: r.Description},
				Help:             sarifText{Text: r.Recommendation},
				DefaultConfiguration: sarifLevel{
					Level: severityToSARIFLevel(r.Severity),
				},
				Properties: map[string]any{
					"security-severity": severityToCVSS(r.Severity),
					"tags":              []string{"security", r.Module},
				},
			})
		}
		if r.Status != check.StatusFail && r.Status != check.StatusError {
			continue
		}
		msg := r.Description
		if len(r.Evidence) > 0 {
			msg = ""
			for i, e := range r.Evidence {
				if i > 0 {
					msg += "\n"
				}
				msg += e
			}
		}
		sarifResults = append(sarifResults, sarifResult{
			RuleID:  r.ID,
			Level:   severityToSARIFLevel(r.Severity),
			Message: sarifText{Text: msg},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifArtifact{URI: "runtime://" + r.Module},
			}}},
		})
	}

	doc := sarifLog{
		Version: "2.1.0",
		Schema:  "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "escape",
				Version:        version,
				InformationURI: "https://github.com/tristanvaquero/escape",
				Rules:          rules,
			}},
			Results: sarifResults,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// SARIF "level" is a coarser scale than ours (note/warning/error/none).
func severityToSARIFLevel(s check.Severity) string {
	switch s {
	case check.SeverityCritical, check.SeverityHigh:
		return "error"
	case check.SeverityMedium:
		return "warning"
	case check.SeverityLow:
		return "note"
	}
	return "none"
}

// GitHub uses CVSS 0..10 in the "security-severity" property to colour findings.
func severityToCVSS(s check.Severity) string {
	switch s {
	case check.SeverityCritical:
		return "9.5"
	case check.SeverityHigh:
		return "7.5"
	case check.SeverityMedium:
		return "5.5"
	case check.SeverityLow:
		return "3.5"
	}
	return "0.0"
}

// --- minimal SARIF type definitions (subset of v2.1.0) ---

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     sarifText      `json:"shortDescription"`
	FullDescription      sarifText      `json:"fullDescription"`
	Help                 sarifText      `json:"help"`
	DefaultConfiguration sarifLevel     `json:"defaultConfiguration"`
	Properties           map[string]any `json:"properties,omitempty"`
}

type sarifLevel struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}
