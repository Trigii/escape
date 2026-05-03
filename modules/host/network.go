package host

import (
	"context"
	"errors"
	"io/fs"
	"strings"

	"github.com/tristanvaquero/escape/internal/engine"
	"github.com/tristanvaquero/escape/pkg/check"
)

// hostNetworkCheck heuristically detects --network=host / hostNetwork: true
// by counting non-loopback interfaces and inspecting the routing table.
// A workload with its own network namespace usually has a single eth0
// (or similar) plus lo. A workload sharing the host network sees every
// interface on the host (often docker0, bridge interfaces, vpn tunnels).
type hostNetworkCheck struct{ check.Base }

func (c *hostNetworkCheck) Run(ctx context.Context) check.Result {
	data, err := DefaultFS.ReadFile("/proc/net/dev")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return check.NewSkip(c, "/proc/net/dev not present")
		}
		return check.NewError(c, err)
	}
	var nonLoopback []string
	for _, line := range strings.Split(string(data), "\n") {
		// header lines start without a leading interface name
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			continue
		}
		name := strings.TrimSpace(line[:i])
		if name == "" || name == "lo" || name == "Inter-" {
			continue
		}
		nonLoopback = append(nonLoopback, name)
	}
	// Heuristic: 4+ non-loopback interfaces is unusual for a workload with
	// its own netns. Tweak if needed.
	if len(nonLoopback) >= 4 || hasHostInterfaceNames(nonLoopback) {
		return check.NewFail(c,
			append([]string{"interfaces visible to workload:"}, nonLoopback...),
			"Drop --network=host (Docker) / hostNetwork: true (Kubernetes). "+
				"The pod should have its own network namespace.")
	}
	res := check.NewPass(c)
	res.Evidence = []string{"non-loopback interfaces: " + strings.Join(nonLoopback, ",")}
	return res
}

// hasHostInterfaceNames returns true when the interface list contains
// names that are typical on a Docker host (bridges, vpn, virtual links).
func hasHostInterfaceNames(ifaces []string) bool {
	hostMarkers := []string{"docker0", "br-", "veth", "cni", "flannel", "weave", "calico", "wg", "tun", "tap"}
	for _, n := range ifaces {
		for _, m := range hostMarkers {
			if strings.HasPrefix(n, m) {
				return true
			}
		}
	}
	return false
}

func init() {
	engine.Register(&hostNetworkCheck{Base: check.Base{
		IDValue:          "host.network.shared",
		NameValue:        "Host network namespace shared",
		ModuleValue:      "host",
		SeverityValue:    check.SeverityHigh,
		DescriptionValue: "Heuristic detection of --network=host / hostNetwork: true via /proc/net/dev.",
	}})
}
