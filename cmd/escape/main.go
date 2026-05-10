// escape is a read-only audit CLI for containers and Kubernetes.
//
// The binary delegates to internal/cli for argument parsing and
// dispatch. main() is intentionally tiny so that integration tests
// can call cli.Run() directly.
package main

import (
	"os"

	"github.com/tristanvaquero/escape/internal/cli"

	// Side-effect imports: registering checks. Each module's init()
	// adds its checks to the global registry.
	_ "github.com/tristanvaquero/escape/modules/cloud"
	_ "github.com/tristanvaquero/escape/modules/container"
	_ "github.com/tristanvaquero/escape/modules/host"
	_ "github.com/tristanvaquero/escape/modules/kubernetes"
	// Side-effect imports: registering attack chains.
	_ "github.com/tristanvaquero/escape/modules/chains"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
