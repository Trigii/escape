# ESCAPE lab

A small Docker Compose lab that exercises every module of `escape` against deliberately-misconfigured containers.

```
clean         ─ hardened control (rootless, read-only, seccomp default, dropped caps)
privileged    ─ --privileged
host-mounts   ─ docker.sock + host bind mounts
caps-galore   ─ explicit cap_add: SYS_ADMIN, SYS_PTRACE, SYS_MODULE, DAC_READ_SEARCH, NET_ADMIN
rootful       ─ uid 0, seccomp=unconfined, apparmor=unconfined, no_new_privs=false, writable rootfs
hostns        ─ pid: host + network_mode: host
```

## Quick start

```bash
# 1. Build the linux-amd64 binary at the repo root
cd ..
make release          # produces dist/escape-linux-amd64

# 2. Spin up the lab and run the audit
cd lab
chmod +x run.sh teardown.sh
./run.sh
```

`run.sh` builds the lab image, brings the six containers up, executes `escape scan --output json` inside each, and asserts that the expected check IDs failed. Output JSON is left under `lab/out/` for inspection.

## What you should see

```
▶ Starting lab containers
▶ Running scans

  ── clean (escape_lab_clean)
    failures: 1
      • container.runtime         (info — "you're in a container")

  ── privileged (escape_lab_privileged)
    failures: 7
      • container.capabilities.dangerous
      • container.mounts.sensitive
      • container.privileged
      • container.runtime
      • host.proc_kcore
      • host.modprobe_path
      • host.devices.raw_block
  ...

▶ Verifying expectations
  ✓  privileged → container.privileged
  ✓  privileged → container.capabilities.dangerous
  ✓  host-mounts → container.mounts.docker_sock
  ...

OK  16 / 16 expectations met
```

## Customising expectations

`expected.txt` is a flat list of `<service> <check-id>` pairs. Add a new misconfiguration to `docker-compose.yml`, list its expected IDs, and re-run.

## Tear down

```bash
./teardown.sh
```

## Important — only run this on disposable infrastructure

Several services request real kernel privileges (`--privileged`, `pid: host`, `network_mode: host`, Docker socket bind-mount). Do **not** start this lab on a host that runs anything you care about. A throwaway VM, a laptop, or a lab cluster is the right place.
