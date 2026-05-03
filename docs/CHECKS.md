# Check catalogue

Each check below is implemented as a single Go file under `modules/<module>/`. All checks are read-only; the "How it works" column lists exactly which paths or env vars the check inspects so you can reproduce the result by hand.

## container

| ID | Severity | How it works |
|---|---|---|
| `container.runtime` | info | Existence of `/.dockerenv`, `/run/.containerenv`; substrings in `/proc/1/cgroup`. |
| `container.user.root` | high | `os.Getuid()` / `os.Getgid()`. |
| `container.capabilities.dangerous` | high | Parses `CapEff:` line in `/proc/self/status` and decodes a curated bitmap. |
| `container.privileged` | critical | Full-cap mask + `rw` mount of `/sys` parsed from `/proc/self/mountinfo`. |
| `container.mounts.docker_sock` | critical | `os.Stat` against `/var/run/docker.sock`, `containerd.sock`, `crio.sock`. |
| `container.mounts.sensitive` | high | Suspicious mount points (`/host`, `/host/etc`, `/host/var/run`) and bind-mounted `/etc/shadow` / `/etc/passwd`. |
| `container.seccomp` | medium | Parses `Seccomp:` line in `/proc/self/status` (0=disabled, 2=filter). |
| `container.no_new_privs` | medium | Parses `NoNewPrivs:` line in `/proc/self/status`. |
| `container.apparmor` | low | Reads `/proc/self/attr/current`. |

## kubernetes

| ID | Severity | How it works |
|---|---|---|
| `k8s.detect` | info | `KUBERNETES_SERVICE_HOST/PORT`; existence of the SA token. |
| `k8s.sa.token` | medium | Existence + size + JWT shape of `/var/run/secrets/kubernetes.io/serviceaccount/token`. **Token value is never logged.** |
| `k8s.sa.namespace` | info | Reads `/var/run/secrets/kubernetes.io/serviceaccount/namespace`. |
| `k8s.sa.ca` | info | `os.Stat` of `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`. |
| `k8s.api.reachable` | medium | Single `net.Dial("tcp", KUBERNETES_SERVICE_HOST:PORT)` with 2s timeout. **No HTTP, no auth.** |

## host

| ID | Severity | How it works |
|---|---|---|
| `host.pid_namespace` | high | Reads `/proc/1/comm`; flags `systemd`/`init`. |
| `host.proc_visibility` | medium | Counts numeric entries in `/proc`; >200 is suspicious. |
| `host.cgroup.writable_v1` | high | Looks for `cgroup` fs type with `rw` options in `/proc/self/mountinfo`. |
| `host.devices.raw_block` | critical | Lists `/dev` and matches `sd*`, `vd*`, `nvme0n1`, `xvd*`. |

## cloud

| ID | Severity | How it works |
|---|---|---|
| `cloud.imds.reachable` | high | Concurrent `net.Dial("tcp", ...)` against AWS/Azure/GCP/Alibaba IMDS endpoints. |
| `cloud.env.credentials` | high | Pattern-matches env var **names**; values are redacted in the output. |

## What's deliberately *not* here

- **No exploit primitives**: no `kexec`, `mount`, `release_agent` writes, `/proc/sys/kernel/core_pattern` overwrites, etc.
- **No HTTP probing**: the API/IMDS checks stop at TCP. We never send the SA token nor request `/latest/meta-data/`.
- **No mutation**: every filesystem call is `Stat` / `ReadFile` / `ReadDir`.
- **No external dependencies**: stdlib only. The whole binary is auditable in an afternoon.

## Roadmap

Ideas for additional read-only checks (PRs welcome):

- `container.runtime.gvisor` / `kata` detection (`runc` vs sandboxed runtimes).
- `k8s.downward_api.leak` — projected fields exposing pod metadata that could fingerprint the cluster.
- `host.kernel.version` — match running kernel against published CVEs (offline DB).
- `cloud.imds.v2_required` — passive detection of IMDSv1 fallback exposure (still without token requests).
- `container.user_namespaces` — detect whether the container runs in a user namespace.
- `container.read_only_root` — detect a writable root filesystem.
