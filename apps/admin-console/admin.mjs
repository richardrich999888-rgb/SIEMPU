import { element as el, field, button, badge, hint, panel, table } from '/apps/unit-client/dom.mjs';

/** Administrative metadata only; never render protected object plaintext. */
export async function renderAdmin(root, helpers) {
  const { api, adminMutation, action, notify, state, verified, download } = helpers;
  const overview = await api('/api/admin/overview');
  state.admin = overview;
  const canWrite = state.user.role === 'admin';
  const units = overview.units || [];
  const users = overview.users || [];
  const devices = overview.devices || [];
  const sessions = overview.sessions || [];
  const policies = overview.policies || [];
  const objects = overview.objects || [];
  const alerts = overview.alerts || [];
  const nameOfUnit = (id) => units.find((u) => u.id === id)?.name || id || '—';
  const nameOfUser = (id) => users.find((u) => u.id === id)?.username || id || '—';
  const redraw = async () => {
    await helpers.refreshAuthority();
    await renderAdmin(root, helpers);
  };
  const select = (options, value) =>
    el(
      'select',
      {},
      options.map(([id, text]) => el('option', { value: id, selected: id === value }, text)),
    );
  const unitOptions = units.map((u) => [u.id, u.name]);
  const tabRoot = el('div');
  const tabs = el('div', { className: 'tabs' });
  let active = state.adminTab || 'overview';
  const refresh = button('Refresh console', action(redraw), 'quiet small');
  function overviewView() {
    return el(
      'div',
      {},
      el(
        'div',
        { className: 'stat-grid' },
        [
          ['Units', units.length],
          ['Active users', users.filter((u) => u.active).length],
          ['Held objects', objects.filter((o) => o.state === 'HELD').length],
          ['Authority epoch', overview.epoch],
        ].map(([label, value]) =>
          el('div', { className: 'stat' }, el('strong', {}, value), el('span', {}, label)),
        ),
      ),
      el(
        'div',
        { className: 'grid' },
        panel(
          'Security events',
          'Local authority events and alerts. External SIEM integration and endpoint detection remain deployment work.',
          alerts.length
            ? el(
                'div',
                { className: 'alert-list' },
                [...alerts]
                  .slice(-25)
                  .reverse()
                  .map((a) =>
                    el(
                      'div',
                      { className: 'alert-row' },
                      a.type || a.eventType || a.code || 'Security event',
                      el('small', {}, a.reason || a.message || a.details?.reason || ''),
                      el(
                        'small',
                        {},
                        a.timestamp
                          ? new Date(a.timestamp).toLocaleString()
                          : 'Recorded by authority',
                      ),
                    ),
                  ),
              )
            : el('div', { className: 'empty' }, 'No security alerts returned by authority.'),
        ),
        panel(
          'Authority health',
          'The control authority owns admission, policy and evidence in one transactional store.',
          el(
            'div',
            { className: 'health-list' },
            el('div', {}, 'Control API', badge('Reachable')),
            el('div', {}, 'Revocation version', String(overview.revocationVersion)),
            el(
              'div',
              {},
              'Active sessions',
              String(sessions.filter((s) => !s.revoked && s.expiresAt > Date.now()).length),
            ),
            el('div', {}, 'Deployment profile', 'Single host / prototype'),
          ),
          el(
            'details',
            {},
            el('summary', {}, 'Inspect measured service metrics'),
            el('pre', {}, JSON.stringify(overview.metrics || {}, null, 2)),
          ),
          button(
            'Check service health',
            action(async () => {
              const health = await api('/health');
              notify(`Health: ${JSON.stringify(health)}`);
            }),
            'quiet small',
          ),
        ),
      ),
      panel(
        'Exchange activity',
        'Content remains outside the administrative dashboard.',
        table(
          ['Object', 'State', 'Mission', 'Sender', 'Recipient'],
          objects
            .slice(-30)
            .reverse()
            .map((o) => [
              (o.id || o.objectId || '').slice(0, 18),
              badge(o.state),
              o.missionId,
              nameOfUser(o.senderUserId),
              nameOfUser(o.recipientUserId),
            ]),
        ),
      ),
    );
  }
  function identityView() {
    const unitName = el('input', {
      required: true,
      maxLength: 80,
      placeholder: 'Synthetic unit name',
    });
    const username = el('input', { required: true, autoComplete: 'off', maxLength: 100 });
    const password = el('input', {
      type: 'password',
      required: true,
      minLength: 12,
      autoComplete: 'new-password',
    });
    const unit = select(unitOptions);
    const role = select(['operator', 'viewer', 'auditor', 'admin'].map((r) => [r, r]));
    const dutyChoices = [
      ['', 'Unassigned'],
      ...[
        'UNIT_COMMANDER',
        'SIGNALS_OFFICER',
        'INTELLIGENCE_ANALYST',
        'FIELD_OPERATOR',
        'AUDIT_OFFICER',
        'SYSTEM_ADMIN',
      ].map((name) => [name, name]),
    ];
    const dutyRole = select(dutyChoices);
    const missions = el('input', {
      required: true,
      placeholder: 'DEMO-MISSION',
      value: state.user.missionIds?.[0] || 'DEMO-MISSION',
    });
    const enrollment = el('div');
    return el(
      'div',
      {},
      panel(
        'Units',
        'Unit identity is enforced by authority, not by browser navigation.',
        table(
          ['Unit', 'Identifier'],
          units.map((u) => [u.name, el('span', { className: 'object-id' }, u.id)]),
        ),
        canWrite
          ? el(
              'form',
              {
                className: 'row section-gap',
                onSubmit: action(async () => {
                  await adminMutation('/api/admin/units', 'POST', { name: unitName.value.trim() });
                  notify('Unit created.');
                  await redraw();
                }),
              },
              field('New unit name', unitName),
              el('button', { type: 'submit' }, 'Create unit'),
            )
          : null,
      ),
      panel(
        'Users & roles',
        'Role or membership changes increment authority state and affect future release.',
        table(
          ['User', 'Unit', 'Role', 'Duty position', 'State', 'Controls'],
          users.map((u) => {
            const assignedRole = select(
              ['operator', 'viewer', 'auditor', 'admin'].map((r) => [r, r]),
              u.role,
            );
            const assignedDuty = select(dutyChoices, u.dutyRole || '');
            return [
              u.username,
              nameOfUnit(u.unitId),
              canWrite ? assignedRole : u.role,
              canWrite ? assignedDuty : u.dutyRole || 'Unassigned',
              badge(u.active ? 'Active' : 'Disabled'),
              canWrite
                ? el(
                    'div',
                    { className: 'row' },
                    button(
                      'Apply role',
                      action(async () => {
                        await adminMutation(`/api/admin/users/${u.id}`, 'PATCH', {
                          role: assignedRole.value,
                        });
                        notify('Role changed.');
                        await redraw();
                      }),
                      'quiet small',
                    ),
                    button(
                      'Apply duty',
                      action(async () => {
                        if (!assignedDuty.value)
                          throw new Error('Select a nonempty duty-position profile.');
                        await adminMutation(`/api/admin/users/${u.id}`, 'PATCH', {
                          dutyRole: assignedDuty.value,
                        });
                        notify('Duty-role restriction saved; current authority policy updated.');
                        await redraw();
                      }),
                      'quiet small',
                    ),
                    button(
                      u.active ? 'Disable' : 'Enable',
                      action(async () => {
                        await adminMutation(`/api/admin/users/${u.id}`, 'PATCH', {
                          active: !u.active,
                        });
                        notify('User state changed.');
                        await redraw();
                      }),
                      u.active ? 'danger small' : 'quiet small',
                    ),
                  )
                : 'Read only',
            ];
          }),
        ),
      ),
      canWrite
        ? panel(
            'Create user',
            'Enroll the TOTP secret through a trusted separate channel. It is shown once in this view.',
            el(
              'form',
              {
                className: 'inline-form',
                onSubmit: action(async () => {
                  const result = await adminMutation('/api/admin/users', 'POST', {
                    username: username.value.trim(),
                    password: password.value,
                    unitId: unit.value,
                    role: role.value,
                    ...(dutyRole.value ? { dutyRole: dutyRole.value } : {}),
                    missionIds: missions.value
                      .split(',')
                      .map((s) => s.trim())
                      .filter(Boolean),
                  });
                  password.value = '';
                  enrollment.replaceChildren(
                    el(
                      'div',
                      { className: 'secret-output section-gap' },
                      el('strong', {}, `Enroll MFA for ${result.user.username}`),
                      el('code', {}, result.totpSecret),
                      hint(
                        'This secret is sensitive. Transfer it through the approved enrollment channel, then clear this view.',
                      ),
                      button(
                        'Clear enrollment secret',
                        () => {
                          enrollment.replaceChildren();
                        },
                        'quiet small',
                      ),
                    ),
                  );
                  notify('User created; complete separate MFA and device enrollment.');
                }),
              },
              field('Username', username),
              field('Initial password (12+ characters)', password),
              field('Unit', unit),
              field('Role', role),
              field('Filed duty-position profile (synthetic)', dutyRole),
              field('Missions (comma-separated)', missions),
              el(
                'div',
                { className: 'full' },
                el('button', { type: 'submit' }, 'Create user & MFA enrollment'),
              ),
            ),
            enrollment,
          )
        : null,
    );
  }
  function deviceView() {
    return el(
      'div',
      {},
      panel(
        'Device lifecycle',
        'Approval authorizes registered software keys. It does not establish hardware integrity.',
        table(
          ['Device', 'Owner', 'State', 'Controls'],
          devices.map((d) => {
            const status = d.status || (d.active ? 'approved' : 'revoked');
            return [
              el('div', {}, d.label || 'Device', el('div', { className: 'object-id' }, d.id)),
              nameOfUser(d.userId),
              badge(status),
              canWrite
                ? el(
                    'div',
                    { className: 'row' },
                    status.toLowerCase() === 'pending'
                      ? button(
                          'Approve',
                          action(async () => {
                            await adminMutation(`/api/admin/devices/${d.id}/approve`, 'POST');
                            notify('Device approved.');
                            await redraw();
                          }),
                          'small',
                        )
                      : null,
                    status.toLowerCase() !== 'revoked'
                      ? button(
                          'Revoke',
                          action(async () => {
                            await adminMutation(`/api/admin/devices/${d.id}/revoke`, 'POST');
                            notify(
                              'Device revoked. Previously released content cannot be recalled.',
                            );
                            await redraw();
                          }),
                          'danger small',
                        )
                      : null,
                  )
                : 'Read only',
            ];
          }),
        ),
      ),
      panel(
        'Session lifecycle',
        'Bearer sessions expire and can be revoked. Each sensitive operation checks current authority.',
        table(
          ['Session', 'User', 'Device', 'Expires', 'Control'],
          sessions.map((s) => [
            el('span', { className: 'object-id' }, s.id),
            nameOfUser(s.userId),
            s.deviceId?.slice(0, 12) || 'Unbound',
            new Date(s.expiresAt).toLocaleString(),
            s.revoked
              ? badge('Revoked')
              : canWrite
                ? button(
                    'Revoke session',
                    action(async () => {
                      await adminMutation(`/api/admin/sessions/${s.id}/revoke`, 'POST');
                      notify('Session revoked.');
                      await redraw();
                    }),
                    'danger small',
                  )
                : 'Read only',
          ]),
        ),
      ),
    );
  }
  function policiesView() {
    const from = select(unitOptions);
    const to = select(unitOptions);
    const mission = el('input', {
      value: state.user.missionIds?.[0] || 'DEMO-MISSION',
      required: true,
    });
    const allow = select([
      ['true', 'Allow'],
      ['false', 'Deny'],
    ]);
    return el(
      'div',
      {},
      panel(
        'Directed exchange policies',
        'Each rule binds the sending unit, receiving unit and mission. No matching allow means no release.',
        table(
          ['From unit', 'To unit', 'Mission', 'Decision'],
          policies.map((p) => [
            nameOfUnit(p.fromUnit),
            nameOfUnit(p.toUnit),
            p.missionId,
            badge(p.allow ? 'Allow' : 'Deny'),
          ]),
        ),
      ),
      canWrite
        ? panel(
            'Change current authority',
            'A committed policy change increments the global epoch. Recipient claims must revalidate at the current epoch.',
            el(
              'form',
              {
                className: 'inline-form',
                onSubmit: action(async () => {
                  const result = await adminMutation('/api/admin/policies', 'PUT', {
                    fromUnit: from.value,
                    toUnit: to.value,
                    missionId: mission.value.trim(),
                    allow: allow.value === 'true',
                  });
                  notify(`Policy committed. Authority epoch ${result.epoch ?? 'changed'}.`);
                  await redraw();
                }),
              },
              field('From unit', from),
              field('To unit', to),
              field('Mission', mission),
              field('Decision', allow),
              el(
                'div',
                { className: 'full' },
                el('button', { type: 'submit' }, 'Commit policy change'),
              ),
            ),
          )
        : null,
      el(
        'p',
        { className: 'warning section-gap' },
        'Release is committed capability issuance, not physical packet transmission. A later policy change cannot recall a key already released.',
      ),
    );
  }
  function evidenceView() {
    const integrationOutput = el('div');
    const external = el('input', { required: true, value: `synthetic-${Date.now()}` });
    const object = el('input', { required: true, placeholder: 'Existing synthetic object UUID' });
    const destination = select(unitOptions);
    const mission = el('input', {
      required: true,
      value: state.user.missionIds?.[0] || 'DEMO-MISSION',
    });
    return el(
      'div',
      {},
      panel(
        'Cryptographic evidence',
        'Download a signed chain and an independently retained checkpoint. Verify with the separate command-line verifier and a trusted public key.',
        el(
          'div',
          { className: 'form-actions' },
          button(
            'Export evidence chain',
            action(async () => {
              const exported = await api('/api/evidence/export');
              await verified(exported.checkpoint, 'Evidence checkpoint');
              download(exported, `siepmu-evidence-${Date.now()}.json`);
              notify('Evidence exported. Use the independent verifier to validate the full chain.');
            }),
          ),
          button(
            'Save external checkpoint',
            action(async () => {
              const checkpoint = await api('/api/evidence/checkpoint');
              await verified(checkpoint, 'Evidence checkpoint');
              download(checkpoint, `siepmu-checkpoint-${Date.now()}.json`);
              notify(
                'Checkpoint downloaded. Retain it independently to detect later suffix truncation.',
              );
            }),
            'quiet',
          ),
          button(
            'Export pinned public key',
            () => download(state.pin, 'siepmu-authority-public-key.json'),
            'quiet',
          ),
        ),
        el('div', { className: 'divider' }),
        el(
          'pre',
          {},
          'node apps/verifier/verify.mjs evidence.json authority-public-key.json --checkpoint saved-checkpoint.json',
        ),
        hint(
          'A valid signature establishes integrity and signer identity. It does not establish the factual truth of a decision or certify the deployment.',
        ),
      ),
      canWrite
        ? panel(
            'Controlled integration boundary',
            'Synthetic schema validation only. No existing military network or service is connected.',
            el(
              'form',
              {
                className: 'inline-form',
                onSubmit: action(async () => {
                  const result = await adminMutation('/api/integration/validate', 'POST', {
                    schemaVersion: 1,
                    externalId: external.value.trim(),
                    objectId: object.value.trim(),
                    destinationUnitId: destination.value,
                    missionId: mission.value.trim(),
                  });
                  integrationOutput.replaceChildren(el('pre', {}, JSON.stringify(result, null, 2)));
                  notify('Synthetic integration request validated. No external delivery occurred.');
                }),
              },
              field('External synthetic reference', external),
              field('Object identifier', object),
              field('Destination unit', destination),
              field('Mission', mission),
              el(
                'div',
                { className: 'full' },
                el('button', { type: 'submit' }, 'Validate synthetic request'),
              ),
            ),
            integrationOutput,
          )
        : null,
    );
  }
  const views = {
    overview: ['Overview', overviewView],
    identities: ['Units & users', identityView],
    devices: ['Devices & sessions', deviceView],
    policies: ['Policies', policiesView],
    evidence: ['Evidence & integration', evidenceView],
  };
  function showTab(name) {
    active = name;
    state.adminTab = name;
    tabs.replaceChildren(
      ...Object.entries(views).map(([key, [label]]) =>
        button(label, () => showTab(key), key === active ? 'active' : ''),
      ),
    );
    tabRoot.replaceChildren(views[name][1]());
  }
  root.replaceChildren(
    el(
      'div',
      { className: 'panel-heading' },
      el(
        'div',
        {},
        el('h2', {}, 'Current authority, visible decisions'),
        hint('Operational controls and security evidence for the synthetic demonstrator.'),
      ),
      refresh,
    ),
    tabs,
    tabRoot,
  );
  showTab(active in views ? active : 'overview');
}
