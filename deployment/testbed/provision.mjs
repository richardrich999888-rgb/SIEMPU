import { mkdirSync, writeFileSync, copyFileSync, rmSync, chmodSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { initDemo } from '../../scripts/bootstrap.mjs';
import { prepareSecureLab, seedLabCustodian } from '../secure/harness.mjs';

const root = resolve(process.argv[2] ?? '.data/testbed'),
  out = resolve(process.argv[3] ?? 'artifacts/testbed');
mkdirSync(root, { recursive: true, mode: 0o700 });
mkdirSync(out, { recursive: true });
const provisioned = await initDemo(join(root, 'control'), { includeAdapter: true }),
  profiles = Object.fromEntries(provisioned.profiles.map((p) => [p.username, p]));
const lab = prepareSecureLab(root),
  pki = lab.pki;
await seedLabCustodian(join(root, 'control'), lab.independent);
pki.issue('unit-admin');
const services = {},
  networks = Object.fromEntries(
    [
      'unit_a',
      'unit_b',
      'unit_denied',
      'unit_admin',
      'authority',
      'ciphertext',
      'custody',
      'monitoring',
      'external',
    ].map((n) => [n, { internal: true }]),
  );
const write = (path, obj) => writeFileSync(path, JSON.stringify(obj), { mode: 0o600, flag: 'wx' });
const roles = [
  'web',
  'control',
  'relay',
  'checkpoint',
  'collector',
  'adapter',
  'unit-a',
  'unit-b',
  'unit-denied',
  'unit-admin',
];
for (const role of roles) {
  const data = join(
    root,
    role === 'checkpoint' ? 'custody' : role === 'collector' ? 'monitor' : role,
  );
  mkdirSync(data, { recursive: true, mode: 0o700 });
  const keydir = join(root, 'keys', role);
  mkdirSync(keydir, { recursive: true, mode: 0o700 });
  for (const name of ['ca.crt', role + '.crt', role + '.key'])
    copyFileSync(join(pki.dir, name), join(keydir, name));
  for (const name of role === 'web'
    ? ['web-client']
    : role === 'control'
      ? ['control-client']
      : role === 'collector'
        ? ['operator-client']
        : role === 'unit-a'
          ? ['adapter-client']
          : [])
    for (const ext of ['crt', 'key'])
      copyFileSync(join(pki.dir, name + '.' + ext), join(keydir, name + '.' + ext));
  const env = {
    NODE_ENV: 'production',
    SIEPMU_PROFILE: 'isolated',
    SIEPMU_DATA_DIR: '/state',
    SIEPMU_TLS_CA: '/keys/ca.crt',
    SIEPMU_PUBLIC_ORIGIN: 'https://web:8080',
    SIEPMU_AUTHORITY_PUBLIC_KEY: '/state/authority-public.json',
  };
  write(join(data, 'authority-public.json'), provisioned.serverPublicKey);
  env[`SIEPMU_${role.toUpperCase()}_TLS_CERT`] = `/keys/${role}.crt`;
  env[`SIEPMU_${role.toUpperCase()}_TLS_KEY`] = `/keys/${role}.key`;
  const pins = {
    control: [pki.pin('web-client')],
    relay: [pki.pin('control-client')],
    checkpoint: [pki.pin('control-client')],
    collector: [pki.pin('control-client'), pki.pin('operator-client')],
    adapter: [pki.pin('adapter-client')],
  };
  if (pins[role]) env[`SIEPMU_${role.toUpperCase()}_TLS_CLIENT_PINS`] = pins[role].join(',');
  const identity = role === 'web' ? 'web-client' : role === 'control' ? 'control-client' : role;
  env[`SIEPMU_${role.toUpperCase()}_CLIENT_TLS_CERT`] = `/keys/${identity}.crt`;
  env[`SIEPMU_${role.toUpperCase()}_CLIENT_TLS_KEY`] = `/keys/${identity}.key`;
  const service = {
    image: process.env.SIEPMU_TESTBED_IMAGE ?? 'syntriass-siepmu:local',
    init: true,
    user: '1000:1000',
    read_only: true,
    cap_drop: ['ALL'],
    security_opt: ['no-new-privileges:true'],
    tmpfs: ['/tmp:rw,noexec,nosuid,size=32m'],
    pids_limit: 128,
    mem_limit: '512m',
    healthcheck: { disable: true },
    volumes: [data + ':/state', keydir + ':/keys:ro'],
    environment: env,
  };
  if (role === 'web') {
    service.command = ['node', 'services/web/server.mjs'];
    service.networks = ['unit_a', 'unit_b', 'unit_denied', 'unit_admin', 'authority'];
    Object.assign(env, { SIEPMU_WEB_HOST: '0.0.0.0', SIEPMU_CONTROL_URL: 'https://control:8081' });
  }
  if (role === 'control') {
    service.command = ['node', 'services/control/server.mjs'];
    service.networks = ['authority', 'ciphertext', 'custody', 'monitoring'];
    Object.assign(env, {
      SIEPMU_CONTROL_HOST: '0.0.0.0',
      SIEPMU_RELAY_URL: 'https://relay:8082',
      SIEPMU_CUSTODY_URL: 'https://checkpoint:8444/v1/checkpoints',
      SIEPMU_CUSTODIAN_PUBLIC_KEY: '/state/custodian-public.json',
      SIEPMU_COLLECTOR_URL: 'https://collector:8445/v1/events',
      SIEPMU_COLLECTOR_PUBLIC_KEY: '/state/collector-public.json',
    });
    copyFileSync(join(root, 'custody/public-key.json'), join(data, 'custodian-public.json'));
    copyFileSync(join(root, 'monitor/public-key.json'), join(data, 'collector-public.json'));
  }
  if (role === 'relay') {
    service.command = ['node', 'services/relay/server.mjs'];
    service.networks = ['ciphertext'];
    env.SIEPMU_RELAY_HOST = '0.0.0.0';
    copyFileSync(join(root, 'control/relay.secret'), join(data, 'relay.secret'));
  }
  if (role === 'checkpoint') {
    service.command = ['node', 'services/evidence/server.mjs'];
    service.networks = ['custody'];
    Object.assign(env, {
      SIEPMU_CUSTODY_HOST: '0.0.0.0',
      SIEPMU_CUSTODY_DB: '/state/checkpoints.sqlite',
      SIEPMU_CUSTODY_SIGNING_KEY: '/state/signing-key.json',
    });
  }
  if (role === 'collector') {
    service.command = ['node', 'services/monitoring/server.mjs'];
    service.networks = ['monitoring'];
    Object.assign(env, {
      SIEPMU_COLLECTOR_HOST: '0.0.0.0',
      SIEPMU_COLLECTOR_DB: '/state/events.sqlite',
      SIEPMU_COLLECTOR_SIGNING_KEY: '/state/signing-key.json',
      SIEPMU_COLLECTOR_SOURCE_PIN: pki.pin('control-client'),
      SIEPMU_COLLECTOR_OPERATOR_PIN: pki.pin('operator-client'),
    });
  }
  if (role === 'adapter') {
    service.command = ['node', 'services/integration/server.mjs'];
    service.networks = ['unit_a', 'external'];
    Object.assign(env, {
      SIEPMU_ADAPTER_HOST: '0.0.0.0',
      SIEPMU_ADAPTER_DB: '/state/adapter.sqlite',
      SIEPMU_ADAPTER_PROFILE: '/state/profile.json',
      SIEPMU_ADAPTER_DESTINATIONS: '/state/destinations.json',
      SIEPMU_PLATFORM_URL: 'https://web:8080',
    });
    write(join(data, 'profile.json'), profiles.adapter);
    write(join(data, 'destinations.json'), [
      {
        userId: profiles.bob.userId,
        unitId: profiles.bob.unitId,
        deviceId: profiles.bob.deviceId,
        encryptionPublicKey: profiles.bob.keys.encryption.publicKey,
      },
    ]);
  }
  if (role.startsWith('unit-')) {
    service.command = ['node', '-e', 'setInterval(()=>{},1000)'];
    service.networks = [role.replaceAll('-', '_'), ...(role === 'unit-a' ? ['external'] : [])];
    const p =
      profiles[
        { 'unit-a': 'alice', 'unit-b': 'bob', 'unit-denied': 'eve', 'unit-admin': 'admin' }[role]
      ];
    write(join(data, 'profile.json'), p);
    write(join(data, 'peer.json'), {
      userId: profiles.bob.userId,
      unitId: profiles.bob.unitId,
      deviceId: profiles.bob.deviceId,
      encryptionPublicKey: profiles.bob.keys.encryption.publicKey,
      senderSigningPublicKey: profiles.alice.keys.signing.publicKey,
      senderDeviceId: profiles.alice.deviceId,
    });
  }
  services[role] = service;
}
// Provisioning aggregate is not mounted into any runtime service.
rmSync(join(root, 'control', 'demo-profiles.json'));
for (const role of roles) {
  const dir = join(root, 'keys', role);
  for (const name of [
    role + '.key',
    ...(role === 'web'
      ? ['web-client.key']
      : role === 'control'
        ? ['control-client.key']
        : role === 'collector'
          ? ['operator-client.key']
          : role === 'unit-a'
            ? ['adapter-client.key']
            : []),
  ])
    chmodSync(join(dir, name), 0o600);
}
writeFileSync(
  join(out, 'compose.json'),
  JSON.stringify({ name: 'siepmu-trl-lab', services, networks }, null, 2) + '\n',
);
writeFileSync(
  join(out, 'topology.json'),
  JSON.stringify(
    {
      synthetic: true,
      zones: roles,
      networks,
      authorityPublicKey: provisioned.serverPublicKey,
      node: process.version,
      root,
      wanEgress: 'Docker internal networks; explicit blocked-egress observation required',
      keyCustody: 'Separate role mounts; host root remains trusted',
    },
    null,
    2,
  ) + '\n',
);
console.log(
  JSON.stringify({
    status: 'PROVISIONED',
    compose: join(out, 'compose.json'),
    zones: roles.length,
  }),
);
