# Changelog

All notable changes to ESCAPE are documented here. The format is loosely
[Keep a Changelog](https://keepachangelog.com/) and the project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **`escape exploit` subcommand** — correlates failing checks into known
  attack chains and prints public-domain PoC commands. Supports
  `table` / `markdown` / `json` outputs and `--from <scan.json>` to
  analyse a saved report.
- **10 attack chains**: docker_sock_pivot, cgroup_release_agent,
  host_disk_mount, sys_ptrace_pivot, sys_module_load, dac_read_search,
  k8s_sa_pivot, imds_aws_creds, kcore_exfil, suid_no_new_privs,
  sensitive_mounts_loot.
- **MITRE ATT&CK and CVE metadata** on `Check` and `Result` — surfaces
  in JSON / SARIF / Markdown output and in the new `docs/ATTACK.md`
  heatmap.
- **`exploit` package** (`pkg/exploit`): `Chain` interface, `Match`
  struct, `Risk` ladder (passive / active-read / write / destructive)
  and a per-chain Registry.

### Changed
- `Result` now carries `attack []string` and `cve []string` fields.
- The README has a dedicated **For pentesters / CTF players** section
  and a comparison table against linpeas / amicontained / CDK / peirates
  / deepce.

### Safety
- `escape exploit` **never executes** the printed commands. The PoC
  steps are emitted as text and the operator is responsible for running
  them under their own scope-of-work and audit trail. A banner reminds
  the user on every invocation.

## [0.2.0] — earlier this iteration

### Added
- 10 high-impact checks (`host.proc_kcore`, `host.proc_kallsyms`,
  `host.modprobe_path`, `host.kernel.version`, `host.network.shared`,
  `host.sysctl.unsafe`, `container.fs.read_only_root`,
  `container.user_namespace`, `container.runtime.sandboxed`,
  `k8s.token.decoded`).
- HTML and SARIF output formats.
- Risk score 0–100 in the table summary and the HTML report.
- `escape explain <id>` subcommand.
- `--only-failures` flag.
- Docker Compose lab under `lab/` with six containers and an automated
  expectation runner.

## [0.1.0] — initial drop

- 20 read-only checks across container, kubernetes, host, cloud.
- Stdlib-only Go skeleton, concurrent runner with timeouts, table /
  JSON / Markdown output, MockFS-driven tests.
