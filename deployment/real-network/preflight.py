"""Read-only inventory. Hashes identify hosts; they do not attest independent administration."""
import hashlib
import importlib.util
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import time


def command(args):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=5)
        return {"exit": r.returncode, "stdout": r.stdout.strip()[:2000], "stderr": r.stderr.strip()[:300]}
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"exit": None, "reason": type(e).__name__}


def digest(path):
    try:
        return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


result = {
    "schemaVersion": 1, "collectedAtUnixMs": time.time_ns() // 1_000_000,
    "kernel": platform.release(), "os": platform.platform(), "machine": platform.machine(),
    "bootIdSha256": digest('/proc/sys/kernel/random/boot_id'),
    "machineIdSha256": digest('/etc/machine-id'), "uid": os.getuid(),
    "node": command(['node', '--version']), "openssl": command(['openssl', 'version']),
    "clock": command(['timedatectl', 'show', '-p', 'NTPSynchronized', '-p', 'TimeUSec']),
    "clockTracking": command(['chronyc', 'tracking']),
    "tools": {n: shutil.which(n) is not None for n in ['ip', 'tc', 'docker', 'tcpdump', 'ssh', 'bwrap', 'clamscan', 'pkcs11-tool']},
    "pythonModules": {n: importlib.util.find_spec(n) is not None for n in ['mininet', 'core']},
    "networkNamespace": command(['unshare', '-n', 'true']),
    "sourceCommit": command(['git', 'rev-parse', 'HEAD']),
    "sourceTree": command(['git', 'rev-parse', 'HEAD^{tree}']),
    "sourceVerification": command(['node', 'deployment/real-network/source.mjs']),
    "administrativeIndependence": "NOT_ATTESTED", "physicalHardware": "NOT_ATTESTED",
}
result['emulation'] = 'AVAILABLE' if result['networkNamespace'].get('exit') == 0 else 'BLOCKED_NETWORK_NAMESPACE_PERMISSION'
print(json.dumps(result, indent=2))
if '--require-emulation' in sys.argv and result['emulation'] != 'AVAILABLE':
    sys.exit(2)
