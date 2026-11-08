# Managed endpoint parser isolation

`ClamAvInspector` accepts an explicitly selected `BubblewrapSandbox`. The original unisolated
adapter remains available for laboratory compatibility. **Select the sandbox in a managed
deployment**; an omitted option is not an isolated scanner. A selected sandbox never falls
back to the unisolated path.

The Linux profile checks pinned launcher/resource-tool bytes and a complete declared runtime
file inventory on every scan. It rejects symlinks, unlisted files and group/world-writable
image entries. A dedicated image contains only the scanner, its dependencies and certificate
material. `prepare-runtime.py` builds that image from the verified ClamAV package for CI;
it is not an unattended deployment installer or a trusted-path attestation system.

The command unshares namespaces including network and PID, drops capabilities, clears the
environment, creates a read-only root and signature mount, uses a 16 MiB private temporary
filesystem, starts a new session, and terminates with its parent. `prlimit` sets a 4 GiB
address-space limit, CPU deadline, 128 descriptors, zero core size and a 16 MiB file limit.
The existing byte, archive expansion, recursion, output and wall-clock limits remain active.
The host-side working directory must be private owner-0700 tmpfs. Operational hosts still
need no-swap/dump policy and protected runtime/database mounts.

These are **per-process limits**, not aggregate cgroup memory/process quotas or a seccomp
policy. Kernel compromise, a malicious administrator, TOCTOU changes to trusted mounts,
all file formats and parser zero-days are not solved by this profile. Browser invocation,
application control, safe viewers and device attestation remain open. Isolation does not
make arbitrary data types approved for IAF handling.

The selected upstream is [Bubblewrap 0.13.1](https://github.com/containers/bubblewrap/releases/tag/v0.13.1),
SHA-256 `0e85c8702248b8dd64144f594147553650cdd0e4c951690345faace79c217c4d` for the release source.
It is built without setuid, with the upstream LGPL-2.1-or-later source/notices retained in
the fetched source tree. Redistributors must supply the applicable source/notices and review
linked libcap/libc licenses. No Bubblewrap binary is committed. The executing prlimit and
shared-library hashes are recorded; OS patch provenance still requires deployment review.
[Upstream security guidance](https://github.com/containers/bubblewrap/security) explicitly
makes the caller responsible for sandbox policy. Versions preceding the 0.12 security fixes
must not be substituted. Selection/advisory review date: 8 November 2026.

`.github/workflows/clamav-native.yml` builds the pinned tool on an ephemeral Linux runner,
loads a path-scoped AppArmor exception for the dedicated root-owned launcher, executes the
native isolation probe and then the three actual ClamAV smoke cases inside the sandbox.
The probe checks denied root/signature writes, invisible host files, network route absence,
zero effective capabilities, tmpfs size and resource limits. No unsupported host is silently
skipped. Failure of native namespaces is a blocking result. The development container cannot
create this namespace; its unit tests check configuration/refusal, not isolation success.

## Ubuntu 24.04 host prerequisite

The hosted probe reproduced `loopback: Failed RTM_NEWADDR: Operation not permitted` before
parser execution. Ubuntu's unprivileged-user-namespace restriction denies setup capabilities
unless the launcher has an explicit profile. The CI host now installs the root-owned pinned
binary at `/usr/local/libexec/siepmu-bwrap` and loads `siepmu-bwrap.apparmor` for that path.
The system-wide restriction is left unchanged. This profile grants namespace setup to the
launcher; it is **not** a restrictive parser AppArmor policy. The fixed runtime invocation
explicitly creates a user namespace, disables further user namespaces, asserts that denial,
and drops all capabilities before executing the parser. The native probe tests the denial.

Administrators must review/provision this host exception; the application never installs it
or relaxes host policy automatically. A host without the required permission refuses scans.
This follows the application-specific option in the official
[Ubuntu 24.04 release notes](https://documentation.ubuntu.com/release-notes/24.04/).
No namespace, capability or filesystem restriction in the parser command is removed to
obtain a passing result. The CI inventory records the profile hash and global restriction.
