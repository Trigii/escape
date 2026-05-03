package host

import (
	"context"
	"errors"
	"io/fs"
	"strings"

	"github.com/tristanvaquero/escape/internal/engine"
	"github.com/tristanvaquero/escape/pkg/check"
)

type hostDeviceExposureCheck struct{ check.Base }

// Looks for raw block devices visible inside the container. A workload
// that can see /dev/sda or /dev/nvme0n1 is one mount call away from
// reading the host root filesystem.
func (c *hostDeviceExposureCheck) Run(ctx context.Context) check.Result {
	entries, err := DefaultFS.ReadDir("/dev")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return check.NewSkip(c, "/dev not present")
		}
		return check.NewError(c, err)
	}
	suspicious := []string{"sda", "sdb", "sdc", "vda", "vdb", "nvme0n1", "nvme1n1", "xvda", "xvdb"}
	var found []string
	for _, e := range entries {
		name := e.Name()
		for _, s := range suspicious {
			if name == s || strings.HasPrefix(name, s+"p") {
				found = append(found, "/dev/"+name)
			}
		}
	}
	if len(found) == 0 {
		return check.NewPass(c)
	}
	return check.NewFail(c,
		append([]string{"raw host block devices visible in /dev:"}, found...),
		"Do not pass --device for host disks. Avoid securityContext.privileged: true.")
}

func init() {
	engine.Register(&hostDeviceExposureCheck{Base: check.Base{
		IDValue:          "host.devices.raw_block",
		NameValue:        "Host raw block devices exposed",
		ModuleValue:      "host",
		SeverityValue:    check.SeverityCritical,
		DescriptionValue: "Detects raw block devices visible inside the workload (sda, vda, nvme...). This is a direct path to host filesystem read access.",
	}})
}
