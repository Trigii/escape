# Check catalogue (30 checks)

Each check below is implemented as a single Go file under `modules/<module>/`. All checks are read-only; the "How it works" column lists exactly which paths or env vars the check inspects so you can reproduce the result by hand.

## container

| ID | Severity | How it works |
|---|---|---|
| `container.runtime` | info | Existence of `/.dockerenv`, `/run/.containerenv`; substrings in `/proc/1/cgroup`. |
| `container.runtime.sandboxed` | info | gVisor (`/proc/version` contains "gVisor"), Kata, Firecracker (DMI sys_vendor). |
| `container.user.root` | high | `os.Getuid()` / `os.Getgid()`. |
| `container.user_namespace` | medium | Parses `/proc/self/uid_map`; `0 0 4294967295` ⇒ root-in==root-out. |
| `container.capabilities.dangerous` | high | Parses `CapEff:` line in `/proc/self/status` and decodes a curated bitmap. |
| `container.privileged` | critical | Full-cap mask + `rw` mount of `/sys` parsed from `/proc/self/mountinfo`. |
| `container.mounts.docker_sock` | critical | `os.Stat` against `/var/run/docker.sock`, `containerd.sock`, `crio.sock`. |
| `container.mounts.sensitive` | high | Suspicious mount points (`/host`, `/host/etc`, `/host/var/run`) and bind-mounted `/etc/shadow` / `/etc/passwd`. |
| `container.fs.read_only_root` | medium | `/` mount entry has `ro` and not `rw`. |
| `container.seccomp` | medium | Parses `Seccomp:` line in `/proc/self/status` (0=disabled, 2=filter). |
| `container.no_new_privs` | medium | Parses `NoNewPrivs:` line in `/proc/self/status`. |
| `container.apparmor` | low | Reads `/proc/self/attr/current`. |

## kubernetes

| ID | Severity | How it works |
|---|---|---|
| `k8s.detect` | info | `KUBERNETES_SERVICE_HOST/PORT`; existence of the SA token. |
| `k8s.sa.token` | medium | Existence + size + JWT shape of `/var/run/secrets/.../token`. **Token value is never logged.** |
| `k8s.token.decoded` | medium | Decodes the JWT payload (base64-url) and surfaces issuer, audience, expiry, namespace, ServiceAccount. **Signature NOT verified, no network call, value not logged.** |
| `k8s.sa.namespace` | info | Reads `/var/run/secrets/.../namespace`. |
| `k8s.sa.ca` | info | `os.Stat` of `/var/run/secrets/.../ca.crt`. |
| `k8s.api.reachable` | medium | Single `net.Dial("tcp", KUBERNETES_SERVICE_HOST:PORT)` with 2s timeout. **No HTTP, no auth.** |

## host

| ID | Severity | How it works |
|---|---|---|
| `host.pid_namespace` | high | Reads `/proc/1/comm`; flags `systemd`/`init`. |
| `host.proc_visibility` | medium | Counts numeric entries in `/proc`; >200 is suspicious. |
| `host.proc_kcore` | critical | `os.Stat("/proc/kcore")` — masked by default in containers; visibility implies broken masking. |
| `host.proc_kallsyms` | medium | Reads first 4KB of `/proc/kallsyms`; redaction means addresses are `0000…`. |
| `host.modprobe_path` | high | Reads `/proc/sys/kernel/modprobe` — building block for CVE-2022-0492. |
| `host.cgroup.writable_v1` | high | `cgroup` fs type with `rw` options in `/proc/self/mountinfo`. |
| `host.network.shared` | high | Heuristic over `/proc/net/dev`: ≥4 non-loopback interfaces or known host names (docker0, br-*, veth*…). |
| `host.devices.raw_block` | critical | Lists `/dev` and matches `sd*`, `vd*`, `nvme0n1`, `xvd*`. |
| `host.kernel.version` | info | `/proc/version`. |
| `host.sysctl.unsafe` | medium | Curated /proc/sys: ptrace_scope, dmesg_restrict, kptr_restrict, unprivileged_bpf_disabled, bpf_jit_harden. |

## cloud

| ID | Severity | How it works |
|---|---|---|
| `cloud.imds.reachable` | high | Concurrent `net.Dial("tcp", ...)` against AWS/Azure/GCP/Alibaba IMDS endpoints. |
| `cloud.env.credentials` | high | Pattern-matches env var **names**; values are redacted in the output. |

## What's deliberately *not* here

- **No exploit primitives**: no `kexec`, `mount`, `release_agent` writes, `/proc/sys/kernel/core_pattern` overwrites, etc.
- **No HTTP probing**: the API/IMDS checks stop at TCP. We never send the SA token nor request `/latest/meta-data/`.
- **No JWT signature verification**: that would either require the API server's public key (active probe) or a shared secret. Claims-only decoding is purely local arithmetic on the token bytes.
- **No mutation**: every filesystem call is `Stat` / `ReadFile` / `ReadDir`.
- **No external dependencies**: stdlib only.

## Roadmap

Ideas for additional read-only checks (PRs welcome):

- `container.user_namespaces` with /proc/self/gid_map & /proc/self/setgroups context.
- `container.tmpfs.size` — overly permissive tmpfs mounts.
- `container.pid_limit` — read cgroup pids.max.
- `container.memory_limit` — read cgroup memory.max.
- `host.kernel.cve_match` — match running kernel against an offline CVE feed.
- `cloud.imds.v2_required` — passive IMDSv1 detection (without sending unauthenticated metadata fetches).
- `k8s.downward_api.leak` — projected fields exposing pod metadata that could fingerprint the cluster.
- `k8s.secrets.in_env` — list env vars that look like secrets injected from `valueFrom.secretKeyRef` (names only).
- `container.fs.suid_binaries` — count unexpected suid binaries.
