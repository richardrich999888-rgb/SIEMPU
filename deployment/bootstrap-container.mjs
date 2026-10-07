import { spawnSync } from 'node:child_process';
import { copyFileSync, chmodSync } from 'node:fs';
const result = spawnSync(process.execPath, ['scripts/bootstrap.mjs', ...process.argv.slice(2)], {
  stdio: 'inherit',
  env: process.env,
});
if (result.status !== 0) process.exit(result.status || 1);
// This shared volume contains only the relay workload secret, never identity keys or profiles.
copyFileSync(
  `${process.env.SIEPMU_DATA_DIR}/relay.secret`,
  '/var/lib/siepmu/relay-auth/relay.secret',
);
chmodSync('/var/lib/siepmu/relay-auth/relay.secret', 0o600);
