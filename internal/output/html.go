package output

import (
	"fmt"
	"html"
	"io"
	"sort"
	"time"

	"github.com/tristanvaquero/escape/pkg/check"
)

// WriteHTML renders a self-contained HTML report — single file, inline
// CSS, no external assets. Designed for sharing with clients.
func WriteHTML(w io.Writer, results []check.Result, version string) error {
	s := summarize(results)
	score, scoreCSS := riskScore(s)
	now := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")

	// Sort failures by severity desc, then ID asc.
	failures := filter(results, func(r check.Result) bool { return r.Status == check.StatusFail })
	sort.SliceStable(failures, func(i, j int) bool {
		if failures[i].Severity != failures[j].Severity {
			return failures[i].Severity > failures[j].Severity
		}
		return failures[i].ID < failures[j].ID
	})
	other := filter(results, func(r check.Result) bool {
		return r.Status == check.StatusPass || r.Status == check.StatusSkip || r.Status == check.StatusError
	})
	sort.SliceStable(other, func(i, j int) bool { return other[i].ID < other[j].ID })

	fmt.Fprint(w, htmlHead)
	fmt.Fprintf(w, `<header>
  <h1>🐒 ESCAPE audit report</h1>
  <div class="meta">
    Tool version <code>%s</code> · Generated %s
  </div>
</header>`, html.EscapeString(version), html.EscapeString(now))

	// Summary cards.
	fmt.Fprint(w, `<section class="cards">`)
	fmt.Fprintf(w, `<div class="card"><div class="big %s">%d</div><div class="lbl">risk score</div></div>`, scoreCSS, score)
	fmt.Fprintf(w, `<div class="card"><div class="big">%d</div><div class="lbl">total checks</div></div>`, s.Total)
	fmt.Fprintf(w, `<div class="card pass"><div class="big">%d</div><div class="lbl">passed</div></div>`, s.Pass)
	fmt.Fprintf(w, `<div class="card fail"><div class="big">%d</div><div class="lbl">failed</div></div>`, s.Fail)
	fmt.Fprintf(w, `<div class="card skip"><div class="big">%d</div><div class="lbl">skipped</div></div>`, s.Skip)
	if s.Error > 0 {
		fmt.Fprintf(w, `<div class="card error"><div class="big">%d</div><div class="lbl">errored</div></div>`, s.Error)
	}
	fmt.Fprint(w, `</section>`)

	if s.Fail > 0 {
		fmt.Fprint(w, `<section class="distrib"><h2>Failures by severity</h2><div class="bars">`)
		for _, sev := range []check.Severity{check.SeverityCritical, check.SeverityHigh, check.SeverityMedium, check.SeverityLow, check.SeverityInfo} {
			n := s.FailBySeverity[sev]
			fmt.Fprintf(w, `<div class="bar sev-%s"><span class="lbl">%s</span><span class="n">%d</span></div>`,
				sev, sev, n)
		}
		fmt.Fprint(w, `</div></section>`)
	}

	// Findings.
	fmt.Fprint(w, `<section><h2>Findings</h2>`)
	if len(failures) == 0 {
		fmt.Fprint(w, `<p class="none">No failures.</p>`)
	}
	for _, r := range failures {
		fmt.Fprintf(w, `<details class="finding sev-%s" open><summary>
  <span class="badge sev-%s">%s</span>
  <span class="title">%s</span>
  <code class="id">%s</code>
</summary>`, r.SeverityLabel, r.SeverityLabel, html.EscapeString(r.SeverityLabel),
			html.EscapeString(r.Name), html.EscapeString(r.ID))
		fmt.Fprintf(w, `<p class="desc">%s</p>`, html.EscapeString(r.Description))
		if len(r.Evidence) > 0 {
			fmt.Fprint(w, `<h4>Evidence</h4><ul class="evidence">`)
			for _, e := range r.Evidence {
				fmt.Fprintf(w, `<li>%s</li>`, html.EscapeString(e))
			}
			fmt.Fprint(w, `</ul>`)
		}
		if r.Recommendation != "" {
			fmt.Fprintf(w, `<h4>Recommendation</h4><p>%s</p>`, html.EscapeString(r.Recommendation))
		}
		if len(r.References) > 0 {
			fmt.Fprint(w, `<h4>References</h4><ul class="refs">`)
			for _, ref := range r.References {
				fmt.Fprintf(w, `<li><a href="%s" target="_blank" rel="noopener">%s</a></li>`,
					html.EscapeString(ref), html.EscapeString(ref))
			}
			fmt.Fprint(w, `</ul>`)
		}
		fmt.Fprint(w, `</details>`)
	}
	fmt.Fprint(w, `</section>`)

	// Other (pass/skip/error) collapsed.
	if len(other) > 0 {
		fmt.Fprint(w, `<section><details><summary class="all-toggle">Show all checks (`)
		fmt.Fprintf(w, `%d)</summary><table class="all"><thead><tr><th>ID</th><th>Module</th><th>Severity</th><th>Status</th><th>Name</th></tr></thead><tbody>`, len(other))
		for _, r := range other {
			fmt.Fprintf(w, `<tr class="status-%s"><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
				r.Status, html.EscapeString(r.ID), html.EscapeString(r.Module),
				html.EscapeString(r.SeverityLabel), html.EscapeString(string(r.Status)),
				html.EscapeString(r.Name))
		}
		fmt.Fprint(w, `</tbody></table></details></section>`)
	}

	fmt.Fprint(w, htmlFoot)
	return nil
}

// riskScore returns a 0..100 weighted risk score plus a CSS class.
func riskScore(s Summary) (int, string) {
	weights := map[check.Severity]int{
		check.SeverityCritical: 16,
		check.SeverityHigh:     8,
		check.SeverityMedium:   4,
		check.SeverityLow:      2,
		check.SeverityInfo:     0,
	}
	if s.Total == 0 {
		return 0, "score-low"
	}
	got := 0
	max := s.Total * weights[check.SeverityCritical]
	for sev, n := range s.FailBySeverity {
		got += n * weights[sev]
	}
	if max == 0 {
		return 0, "score-low"
	}
	pct := got * 100 / max
	switch {
	case pct >= 50:
		return pct, "score-crit"
	case pct >= 25:
		return pct, "score-high"
	case pct >= 10:
		return pct, "score-med"
	}
	return pct, "score-low"
}

const htmlHead = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>ESCAPE audit report</title>
<style>
:root{--bg:#0d1117;--fg:#e6edf3;--mut:#7d8590;--brd:#30363d;--card:#161b22;
  --crit:#f85149;--high:#fb8500;--med:#d29922;--low:#3fb950;--info:#58a6ff;
  --pass:#3fb950;--fail:#f85149;--skip:#7d8590;--err:#bc8cff;}
*{box-sizing:border-box}
body{font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  margin:0;background:var(--bg);color:var(--fg);padding:24px;max-width:1100px;margin:0 auto}
header{margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid var(--brd)}
h1{margin:0;font-size:24px}
h2{margin-top:32px;font-size:18px;border-bottom:1px solid var(--brd);padding-bottom:6px}
h4{margin:12px 0 4px;font-size:13px;color:var(--mut);text-transform:uppercase;letter-spacing:.05em}
.meta{color:var(--mut);font-size:13px;margin-top:6px}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  background:#1f242c;padding:1px 6px;border-radius:4px;font-size:12px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:16px 0}
.card{background:var(--card);border:1px solid var(--brd);border-radius:8px;padding:14px;text-align:center}
.card .big{font-size:28px;font-weight:600}
.card .lbl{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.05em;margin-top:4px}
.card.pass .big{color:var(--pass)}
.card.fail .big{color:var(--fail)}
.card.skip .big{color:var(--skip)}
.card.error .big{color:var(--err)}
.score-crit{color:var(--crit)}
.score-high{color:var(--high)}
.score-med{color:var(--med)}
.score-low{color:var(--low)}
.distrib .bars{display:flex;gap:8px;flex-wrap:wrap}
.bar{background:var(--card);border:1px solid var(--brd);border-radius:6px;padding:8px 12px;
  display:inline-flex;align-items:center;gap:8px;font-size:13px}
.bar.sev-critical{border-color:var(--crit)}
.bar.sev-high{border-color:var(--high)}
.bar.sev-medium{border-color:var(--med)}
.bar.sev-low{border-color:var(--low)}
.bar .n{font-weight:600}
.finding{background:var(--card);border:1px solid var(--brd);border-left-width:4px;
  border-radius:6px;margin-bottom:10px;padding:10px 14px}
.finding.sev-critical{border-left-color:var(--crit)}
.finding.sev-high{border-left-color:var(--high)}
.finding.sev-medium{border-left-color:var(--med)}
.finding.sev-low{border-left-color:var(--low)}
.finding.sev-info{border-left-color:var(--info)}
.finding summary{cursor:pointer;list-style:none;display:flex;align-items:center;gap:10px}
.finding summary::-webkit-details-marker{display:none}
.badge{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;
  padding:2px 8px;border-radius:999px;background:#1f242c;color:#fff}
.badge.sev-critical{background:var(--crit)}
.badge.sev-high{background:var(--high)}
.badge.sev-medium{background:var(--med);color:#000}
.badge.sev-low{background:var(--low);color:#000}
.badge.sev-info{background:var(--info);color:#000}
.title{font-weight:600;flex:1}
.id{margin-left:auto}
.desc{color:var(--mut)}
.evidence,.refs{margin:0;padding-left:20px}
.evidence li{font-family:ui-monospace,monospace;font-size:13px;line-height:1.7}
table.all{width:100%;border-collapse:collapse;margin-top:8px;font-size:13px}
table.all th,table.all td{padding:6px 10px;border-bottom:1px solid var(--brd);text-align:left}
table.all tr.status-skip td{color:var(--mut)}
.all-toggle{cursor:pointer;color:var(--info)}
.none{color:var(--low);font-weight:600}
a{color:var(--info)}
</style></head><body>`

const htmlFoot = `<footer style="margin-top:32px;color:var(--mut);font-size:12px;
  border-top:1px solid var(--brd);padding-top:12px">
  Generated by escape — read-only container/Kubernetes auditor.
</footer></body></html>`
