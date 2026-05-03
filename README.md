# 🐒 escape

> **ESC + APE** — read-only audit CLI for containers and Kubernetes.
> Enumerates the misconfigurations that real-world *container escapes* live on, without ever pulling the trigger.

`escape` is a single-binary, zero-dependency tool in Go. Drop it inside a container or pod and it tells you, in seconds, whether the workload is one CVE away from owning the host.

It does **not** exploit anything. Every check is read-only: open files in `/proc`, parse env vars, perform passive TCP probes. No syscalls that mutate state, no API requests with stolen tokens, no `mount`, no `kexec`. Safe to run on any environment you're authorized to audit.

---

## Why "escape"?

Container escapes — privilege escalations from a workload to the host or cluster — usually require nothing more exotic than a bad config: a `--privileged` flag, a mounted Docker socket, a stray `CAP_SYS_ADMIN`. `escape` enumerates exactly those preconditions, so you can find them before someone else does.

The name is also a wink: when you find what `escape` is looking for, that's how you'd get out.

---

## Install

### From source
```bash
git clone https://github.com/tristanvaquero/escape.git
cd escape
make build
./dist/escape version
```

### Cross-compiled binaries
```bash
make release
ls dist/
# escape-linux-amd64
# escape-linux-arm64
# escape-darwin-arm64
```

The binary is statically linked stdlib-only — copy it into a container and run.

---

## Usage

```bash
escape scan                                    # full audit, table output
escape scan --output json --output-file r.json # machine-readable
escape scan --output markdown --output-file report.md
escape scan --module container,kubernetes
escape scan --id "container.*" --verbose
escape scan --min-severity high --fail-on critical   # CI gate
escape list-checks                             # show every registered check
escape list-checks --output json
escape version
```

### Flags (`scan`)

| Flag | Default | Purpose |
|---|---|---|
| `--output` | `table` | `table` / `json` / `markdown` / `html` / `sarif` |
| `--output-file` | _(stdout)_ | Write to a file instead of stdout |
| `--module` | _(all)_ | Comma-separated: `container`, `kubernetes`, `host`, `cloud` |
| `--id` | _(all)_ | Comma-separated check IDs; trailing `*` is a glob |
| `--min-severity` | `info` | Drop findings below this severity |
| `--fail-on` | `info` | Exit non-zero when any failure ≥ severity (use `info` to never fail) |
| `--only-failures` | `false` | In table output, hide passes/skips |
| `--parallelism` | `8` | Max concurrent checks |
| `--timeout` | `5s` | Per-check timeout |
| `--global-timeout` | `60s` | Whole-run budget (`0` = none) |
| `--no-color` | `false` | Disable ANSI in table output |
| `--verbose` | `false` | Show evidence even on passing checks |
| `--quiet` | `false` | Silence stderr logging |

### Other commands

```bash
escape explain container.privileged host.proc_kcore
# Prints metadata + remediation for those checks without running them.
# Useful when triaging a finding from a saved JSON/SARIF report.

escape list-checks --module host --output json
# Browse the catalogue.
```

---

## What `escape` checks

| Module | ID | Severity | What it looks at |
|---|---|---|---|
| container | `container.runtime` | info | Detects Docker/containerd/CRI-O via marker files |
| container | `container.user.root` | high | UID 0 inside the workload |
| container | `container.capabilities.dangerous` | high | `CapEff` bits (CAP_SYS_ADMIN, CAP_SYS_MODULE, CAP_BPF, …) |
| container | `container.privileged` | critical | Full caps + writable `/sys` heuristic |
| container | `container.mounts.docker_sock` | critical | `docker.sock`, `containerd.sock`, `crio.sock` reachable |
| container | `container.mounts.sensitive` | high | Host paths bind-mounted into the container |
| container | `container.seccomp` | medium | Seccomp filter mode in `/proc/self/status` |
| container | `container.no_new_privs` | medium | `NoNewPrivs` bit |
| container | `container.apparmor` | low | AppArmor profile (or `unconfined`) |
| kubernetes | `k8s.detect` | info | Detects in-cluster execution |
| kubernetes | `k8s.sa.token` | medium | ServiceAccount token mount (value never logged) |
| kubernetes | `k8s.sa.namespace` | info | Pod namespace |
| kubernetes | `k8s.sa.ca` | info | API server CA bundle present |
| kubernetes | `k8s.api.reachable` | medium | Passive TCP probe of the in-cluster API |
| host | `host.pid_namespace` | high | Heuristic for `hostPID: true` |
| host | `host.proc_visibility` | medium | Excessive PIDs in `/proc` |
| host | `host.cgroup.writable_v1` | high | Writable cgroup v1 (CVE-2022-0492 prereq) |
| host | `host.devices.raw_block` | critical | Raw block devices (sda, vda, nvme…) in `/dev` |
| cloud | `cloud.imds.reachable` | high | Passive TCP probe of well-known IMDS endpoints |
| cloud | `cloud.env.credentials` | high | Suspicious env var names (values redacted) |
| container | `container.fs.read_only_root` | medium | / mounted read-only |
| container | `container.user_namespace` | medium | uid_map shows root inside == root on host |
| container | `container.runtime.sandboxed` | info | gVisor / Kata / Firecracker fingerprint |
| host | `host.proc_kcore` | critical | /proc/kcore visible (host RAM read) |
| host | `host.proc_kallsyms` | medium | Unredacted kernel symbols (KASLR bypass aid) |
| host | `host.modprobe_path` | high | /proc/sys/kernel/modprobe readable (CVE-2022-0492) |
| host | `host.kernel.version` | info | /proc/version |
| host | `host.network.shared` | high | Shared host network namespace heuristic |
| host | `host.sysctl.unsafe` | medium | ptrace_scope, dmesg_restrict, kptr_restrict… |
| kubernetes | `k8s.token.decoded` | medium | Passive JWT claim decode (no signature, no API call) |

That's **30 checks across 4 modules**. Adding more is a matter of dropping a file in `modules/<area>/` with an `init()` that calls `engine.Register`.

---

## Example output

### Console (table)
```
  ID                              SEVERITY  STATUS  CHECK
  container.apparmor              low       pass    AppArmor profile applied
  container.capabilities.dangerous high      fail    Dangerous Linux capabilities present
      · CapEff=0x00000000a80425fb
      · CAP_SYS_ADMIN (near-root inside the container; many escapes pivot through it)
      · CAP_DAC_OVERRIDE (bypass DAC for write)
      → Drop capabilities you don't need (--cap-drop=ALL then --cap-add only the strictly required) ...
  container.mounts.docker_sock    critical  fail    Container runtime socket exposed
      · runtime socket(s) reachable from inside the container:
      · /var/run/docker.sock
      → Never bind-mount the runtime socket into a workload. ...
  container.privileged            critical  pass    Privileged container
  container.runtime               info      fail    Container runtime detection
  ...

  Summary:  total=20 pass=12 fail=6 skip=2 error=0
  Failed:    critical=1  high=3  medium=2  low=0  info=0
```

### JSON
```json
{
  "tool": "escape",
  "version": "v0.1.0-dev",
  "generated_at": "2026-05-02T13:21:08Z",
  "summary": {
    "Total": 20,
    "Pass": 12,
    "Fail": 6,
    "Skip": 2,
    "Error": 0,
    "FailBySeverity": { "0": 0, "1": 0, "2": 2, "3": 3, "4": 1 }
  },
  "results": [
    {
      "id": "container.capabilities.dangerous",
      "name": "Dangerous Linux capabilities present",
      "module": "container",
      "severity": 3,
      "severity_label": "high",
      "status": "fail",
      "description": "Inspects CapEff in /proc/self/status ...",
      "evidence": [
        "CapEff=0x00000000a80425fb",
        "CAP_SYS_ADMIN (near-root inside the container; many escapes pivot through it)"
      ],
      "recommendation": "Drop capabilities you don't need ...",
      "started_at": "2026-05-02T13:21:08.124Z",
      "duration_ns": 412398
    }
  ]
}
```

### Markdown
```markdown
# ESCAPE Audit Report

_Tool version: `v0.1.0-dev` — generated: 2026-05-02T13:21:08Z_

## Summary

| Metric | Count |
|---|---|
| Total checks | 20 |
| Passed | 12 |
| Failed | 6 |
...

## Findings

### CRITICAL — Container runtime socket exposed `container.mounts.docker_sock`

- **Module:** container
- **Description:** Detects whether docker.sock, containerd.sock or crio.sock are reachable...
- **Evidence:**
    - runtime socket(s) reachable from inside the container:
    - /var/run/docker.sock
- **Recommendation:** Never bind-mount the runtime socket into a workload...
```

See [`examples/`](examples/) for full sample reports.

---

## Architecture

```
escape/
├── cmd/escape/          # main() — wires modules into the registry
├── internal/
│   ├── cli/             # subcommand router (stdlib flag, no Cobra)
│   ├── engine/          # registry + concurrent runner with timeouts
│   ├── output/          # table / json / markdown renderers
│   ├── logging/         # stdlib log wrapper, levelled
│   └── config/          # validated run-config struct
├── pkg/check/           # public Check interface, Result struct, Severity
├── modules/
│   ├── container/       # in-container checks
│   ├── kubernetes/      # in-pod K8s checks
│   ├── host/            # host-namespace leak checks
│   └── cloud/           # IMDS / cred env vars
├── tests/               # unit tests + MockFS
└── docs/
```

### Adding a check

```go
// modules/container/my_check.go
package container

import (
    "context"
    "github.com/tristanvaquero/escape/internal/engine"
    "github.com/tristanvaquero/escape/pkg/check"
)

type myCheck struct{ check.Base }

func (c *myCheck) Run(ctx context.Context) check.Result {
    // Read-only logic only.
    return check.NewPass(c)
}

func init() {
    engine.Register(&myCheck{Base: check.Base{
        IDValue:       "container.my_check",
        NameValue:     "My new check",
        ModuleValue:   "container",
        SeverityValue: check.SeverityMedium,
        DescriptionValue: "...",
    }})
}
```

The new check appears automatically in `escape list-checks` and `escape scan`.

---

## Lab

A Docker Compose lab that exercises every module against deliberately-misconfigured containers ships under [`lab/`](lab/). Six services demonstrate distinct misconfiguration classes (privileged, host mounts, capability buffet, rootful, host PID/network, plus a hardened control). The runner asserts expected findings and exits non-zero on regressions.

```bash
make release   # produces dist/escape-linux-amd64
make lab       # builds lab images, runs scan in each, verifies findings
make lab-down  # tear down
```

⚠️ **The lab requests real kernel privileges.** Run it on a throwaway VM, never on a host you care about. See [`lab/README.md`](lab/README.md) for details.

## CI integration

### Plain JSON gate

```yaml
- name: container audit
  run: |
    docker run --rm \
      -v $(pwd)/dist/escape-linux-amd64:/escape:ro \
      <your-image> /escape scan --output json --output-file /tmp/escape.json --fail-on high
```

`escape` exits with code 1 when a finding meets `--fail-on`.

### GitHub Code Scanning (SARIF)

```yaml
- name: escape audit
  run: docker exec my-app /escape scan --output sarif --output-file escape.sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: escape.sarif
```

Findings show up in the **Security** tab with severity badges driven by the `security-severity` property emitted by the SARIF formatter.

---

## ⚠️ Ethical use

`escape` is for **authorized auditing only**. Run it against:

- containers/clusters you own,
- environments you've been explicitly authorized to assess (signed scope),
- bug-bounty targets whose program rules permit enumeration.

Do not run `escape` against infrastructure you don't have permission to inspect. The tool deliberately performs no exploitation, but the output (e.g. "IMDS reachable, SA token mounted") is information that could feed an attack chain — handle reports with the same care you would handle penetration-test findings.

---

## License

MIT — see [LICENSE](LICENSE).
