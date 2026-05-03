# ESCAPE Audit Report

_Tool version: `v0.1.0-dev` — generated: 2026-05-02T13:21:08Z_

## Summary

| Metric | Count |
|---|---|
| Total checks | 20 |
| Passed | 10 |
| Failed | 5 |
| Skipped | 5 |
| Errored | 0 |

### Failures by severity

| Severity | Count |
|---|---|
| critical | 1 |
| high | 3 |
| medium | 0 |
| low | 1 |
| info | 1 |

## Findings

### CRITICAL — Container runtime socket exposed `container.mounts.docker_sock`

- **Module:** container
- **Description:** Detects whether docker.sock, containerd.sock or crio.sock are reachable from inside the container — equivalent to giving root on the host.
- **Evidence:**
    - runtime socket(s) reachable from inside the container:
    - /var/run/docker.sock
- **Recommendation:** Never bind-mount the runtime socket into a workload. If the container needs to talk to the cluster API, use a ServiceAccount with a least-privilege RBAC role instead.
- **References:**
    - <https://attack.mitre.org/techniques/T1611/>

### HIGH — Cloud instance metadata reachable `cloud.imds.reachable`

- **Module:** cloud
- **Description:** Performs a passive TCP probe of well-known IMDS endpoints. No HTTP, no token requests.
- **Evidence:**
    - AWS / Azure / GCP IMDS @ 169.254.169.254:80 — TCP open
- **Recommendation:** Block egress to 169.254.169.254 from workloads that don't need it. On EKS, require IMDSv2 (HttpTokens=required, hop-limit=1). On GKE, prefer Workload Identity over node-level service accounts.

### HIGH — Container running as root `container.user.root`

- **Module:** container
- **Description:** Detects whether the workload's effective UID is 0.
- **Evidence:**
    - running as uid=0 gid=0 (root)
- **Recommendation:** Set a non-root USER in the Dockerfile or runAsNonRoot: true in the PodSecurityContext.

### HIGH — Dangerous Linux capabilities present `container.capabilities.dangerous`

- **Module:** container
- **Evidence:**
    - CapEff=0x00000000a80425fb
    - CAP_SYS_ADMIN (near-root inside the container; many escapes pivot through it)
    - CAP_NET_ADMIN (modify routing/firewalling, sniff networks)
- **Recommendation:** Drop capabilities you don't need.

### LOW — AppArmor profile applied `container.apparmor`

- **Evidence:**
    - AppArmor profile: unconfined

### INFO — Container runtime detection `container.runtime`

- **Evidence:**
    - detected runtime: docker
    - /.dockerenv exists

## Skipped / Errored

| ID | Status | Reason |
|---|---|---|
| `k8s.api.reachable` | skip | not running in Kubernetes |
| `k8s.detect` | skip | no Kubernetes environment indicators found |
| `k8s.sa.ca` | skip | not running in Kubernetes |
| `k8s.sa.namespace` | skip | not running in Kubernetes |
| `k8s.sa.token` | skip | not running in Kubernetes |
