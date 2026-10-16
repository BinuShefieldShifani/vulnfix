# Sandbox hardening

VulnFix executes untrusted code in two places: it compiles/runs model-generated
patches, and it runs exploit drivers against patched code. Both must be isolated.

## What is enforced today (process-level, in `eval/sandbox_hardened.py`)

| Protection | Mechanism | Effect |
|---|---|---|
| Memory cap (512 MB default) | `RLIMIT_AS` | a patch can't exhaust RAM |
| CPU-time cap (20 s default) | `RLIMIT_CPU` | kills runaway computation (independent of wall clock) |
| Process-count cap (64) | `RLIMIT_NPROC` | blocks fork bombs |
| File-size cap (50 MB) | `RLIMIT_FSIZE` | can't fill the disk |
| Isolated working dir | per-run `mkdtemp`, removed after | writes don't escape, no residue |
| Stripped environment | only PATH/HOME/LANG kept | no secrets leak into the child |
| Wall-clock timeout | `subprocess` timeout | hard stop regardless of CPU accounting |
| New session | `os.setsid()` | child can't signal the parent's process group |

The resource limits are POSIX/Linux-only. On platforms without `setrlimit`
(e.g. macOS) the runner still isolates the working dir, strips the env, and
enforces the wall-clock timeout; it reports `limits_applied=False` so callers
know the OS limits were skipped.

Network is intentionally left available: some exploit and behavior oracles bind
`localhost`. See the production section for egress restriction.

## What a production deployment should add (not built here)

- **Container / microVM isolation**: run each remediation in a disposable
  container, or gVisor / Firecracker for stronger kernel isolation. This is the
  real boundary for genuinely hostile input; process-level limits are a
  mitigation, not a jail.
- **Egress restriction**: a default-deny network namespace, allowing only the
  localhost traffic the oracles need.
- **Seccomp / syscall filtering**: restrict the child to the syscalls it needs.
- **Read-only root filesystem** with only the per-run temp dir writable.
- **Non-root, unprivileged user** with dropped capabilities.

These are standard container-platform features; the point of the process-level
layer here is that the prototype never runs untrusted code fully unconstrained,
and the path to production isolation is explicit.
