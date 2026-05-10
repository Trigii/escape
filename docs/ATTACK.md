# MITRE ATT&CK coverage

ESCAPE checks and exploit chains both carry MITRE ATT&CK technique IDs. This page is the heatmap.

## Containers / Escape to Host (T1611)

| Where it appears | Why |
|---|---|
| `container.privileged` (check) | Full caps + writable /sys = host-equivalent. |
| `container.mounts.docker_sock` (check) | Docker daemon access from inside ⇒ host root in one `docker run`. |
| `container.capabilities.dangerous` (check) | CAP_SYS_ADMIN, CAP_SYS_MODULE etc. as direct escape primitives. |
| `host.cgroup.writable_v1` (check) | release_agent escape primitive. |
| `host.modprobe_path` (check) | Building block for CVE-2022-0492. |
| `host.devices.raw_block` (check) | Mount host disk → read /etc/shadow. |
| `chain.docker_sock_pivot` | Pivot via Docker socket. |
| `chain.cgroup_release_agent` | release_agent abuse. |
| `chain.host_disk_mount` | Block-device mount. |
| `chain.sys_module_load` | Load arbitrary kernel module. |
| `chain.sys_ptrace_pivot` | ptrace into host PID 1. |

## Deploy Container (T1610)

`container.mounts.docker_sock`, `chain.docker_sock_pivot`, `k8s.api.reachable` (when chained with a privileged-creating SA).

## Credentials from Cloud Instance Metadata (T1552/005)

`cloud.imds.reachable`, `chain.imds_aws_creds`.

## Credentials from Container API (T1552/007)

`k8s.sa.token`, `k8s.token.decoded`, `chain.k8s_sa_pivot`.

## Credentials from Files (T1552/001)

`cloud.env.credentials`.

## OS Credential Dumping (T1003)

`host.proc_kcore`, `host.devices.raw_block`, `chain.kcore_exfil` (T1003.008 — /etc/passwd & /etc/shadow).

## Process Injection — Ptrace (T1055.008)

`chain.sys_ptrace_pivot`.

## Abuse Elevation Control Mechanism — Setuid/Setgid (T1548/001)

`container.no_new_privs`, `chain.suid_no_new_privs`.

## Exploitation for Privilege Escalation (T1212)

`host.proc_kcore`, `host.proc_kallsyms`.

## Valid Accounts — Cloud (T1078/004)

`chain.k8s_sa_pivot` (lateral movement once SA token is in hand).

---

To see the ATT&CK IDs of a specific finding or chain in the wild:

```bash
escape scan --output json | jq '.results[] | select(.attack) | {id, attack}'
escape exploit --output json | jq '.chains[] | {id, attack}'
```
