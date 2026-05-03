package cli

// Version is the running tool version. Overridden at build time via
//
//	go build -ldflags "-X github.com/tristanvaquero/escape/internal/cli.Version=v0.2.0"
var Version = "v0.1.0-dev"

// Banner is printed at the top of `escape version` and embedded in
// JSON/Markdown reports.
const Banner = `
   ▄▄▄▄▄ ▄▄▄▄▄ ▄▄▄▄▄ ▄▄▄▄▄ ▄▄▄▄▄ ▄▄▄▄▄
   █     █     █     █▄▄▄█ █▄▄▄█ █▄▄▄▄
   █▄▄▄▄ █▄▄▄▄ █▄▄▄▄ █   █ █     █▄▄▄▄
   ESCAPE — read-only container/Kubernetes auditor
`
