import { buildInfo } from './build-info.mjs';

// An authenticated observation of this process, not a TRL assignment or deployment approval.
export function missionReadiness(authority) {
  const deployment = authority.deployment;
  const check = (id, label, observed, detail) => ({
    id,
    label,
    status: observed === true ? 'OBSERVED' : observed === false ? 'GAP' : 'UNKNOWN',
    detail,
  });
  const checks = [
    check(
      'control-mtls',
      'Authority service authentication',
      deployment.controlMutualTls,
      'Actual control-server mTLS options. Gateway and relay configuration require separate verification.',
    ),
    check(
      'https-origin',
      'HTTPS browser origin',
      deployment.publicOriginHttps,
      'Configured origin only. Certificate trust, ingress and external reachability are not established by this value.',
    ),
    check(
      'custody',
      'Independent custody configured',
      Boolean(authority.recoveryGuard),
      'A configured guard does not establish separate administration or an available custodian.',
    ),
    check(
      'monitoring',
      'Telemetry exporter configured',
      deployment.monitoringConfigured,
      'Exporter configuration only. Collector delivery and SOC response require separate evidence.',
    ),
    check(
      'lab-crypto',
      'Laboratory PQC disabled',
      !authority.crypto.allowPqcLab,
      'Laboratory providers must remain excluded from operational release candidates.',
    ),
  ];
  const gates = [
    [
      'PS69-01',
      'IAF requirements and environment',
      'IAF sponsor',
      'Agreed personnel/device enrolment, duty roles, traffic classification, interfaces and representative deployment environment.',
    ],
    [
      'PS69-02',
      'Cryptographic qualification',
      'SYNTRIASS and sponsor-designated assessor',
      'Sponsor-approved algorithm/provider and key-custody path; independent review and the required SAG process remain pending.',
    ],
    [
      'PS69-03',
      'Public Internet assessment',
      'Independent assessor',
      'Penetration test, identity recovery, device loss, relay outage, replay, traffic floods, monitoring and incident-response evidence.',
    ],
    [
      'PS69-04',
      'Representative system trials',
      'SYNTRIASS and IAF sponsor',
      'Separate hosts, agreed WAN/load/outage conditions, restore drills, witnessed mission workflow and measured acceptance criteria.',
    ],
    [
      'PS69-05',
      'Final configuration qualification',
      'IAF sponsor and evaluation authority',
      'Frozen complete system, reproducible release, operator/training/maintenance manuals and documented qualification results.',
    ],
  ].map(([id, label, owner, evidenceNeeded]) => ({
    id,
    label,
    owner,
    evidenceNeeded,
    status: 'EVIDENCE_REQUIRED',
  }));
  return {
    schemaVersion: 1,
    observedAt: new Date().toISOString(),
    mission:
      'IAF DISC-14 PS-69: authorized personnel exchange protected information over the public Internet',
    releaseDecision: 'NOT_QUALIFIED',
    baseline: {
      provisionalTrl: 4,
      revision: '09b18103268603b35a9801b2679fa589bf54160c',
      source: 'docs/engineering/CURRENT_STATE.md',
      note: 'Historical repository self-assessment; these runtime observations do not assign a TRL to this build.',
    },
    build: buildInfo(),
    checks,
    recovery: {
      configured: Boolean(authority.recoveryGuard),
      state: authority.recoveryGuard?.state ?? 'NOT_CONFIGURED',
      note: 'State observed during this authorized request; every release still revalidates current custody and policy.',
    },
    crypto: {
      laboratoryEnabled: authority.crypto.allowPqcLab,
      policy: authority.crypto.policy(),
      inventory: authority.crypto.inventory(),
    },
    qualificationGates: gates,
    limits: [
      'Synthetic-data prototype. Operational authorization and qualification have not been established.',
      'Single authority database; no high-availability or horizontal-scaling claim.',
      'Endpoint compromise and already released plaintext remain outside retroactive revocation.',
      'Observed configuration is not evidence of end-to-end security or TRL 8.',
    ],
  };
}
