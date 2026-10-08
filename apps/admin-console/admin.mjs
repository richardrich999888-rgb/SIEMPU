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
  const alerts = [...(overview.alerts || [])].sort((a, b) => b.timestamp - a.timestamp);
  const counters = overview.metrics?.counters || {};
  const objectCounts = overview.metrics?.objects || {};
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
          ['Held objects', objectCounts.HELD || 0],
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
          'Latest 25 returned alerts, newest first. The authority retains a bounded recent-alert sample; these are not all-time totals.',
          alerts.length
            ? el(
                'div',
                { className: 'alert-list' },
                alerts
                  .slice(0, 25)
                  .map((a) =>
                    el(
                      'div',
                      { className: 'alert-row' },
                      a.kind || a.type || a.eventType || a.code || 'Security event',
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
        'Release and security observations',
        'Authority counters are cumulative for this database. Alert counts below cover only the returned recent sample.',
        table(
          ['Observation', 'Measured value'],
          [
            ['Pending objects', objectCounts.PENDING || 0],
            ['Ready objects', objectCounts.READY || 0],
            ['Held objects', objectCounts.HELD || 0],
            ['Key releases committed', counters.released || 0],
            ['Policy evaluations', counters.policyEvaluations || 0],
            ['HTTP request errors', counters.requestErrors || 0],
            [
              'Authentication failures in recent sample',
              alerts.filter((a) => a.kind === 'AUTH_FAILURE').length,
            ],
            [
              'Authority changes in recent sample',
              alerts.filter((a) => a.kind === 'AUTHORITY_CHANGED').length,
            ],
            ['Approved software devices', devices.filter((d) => d.status === 'approved').length],
            ['Revoked devices', devices.filter((d) => d.status === 'revoked').length],
          ],
        ),
        hint(
          'Device approval records authorization of registered keys; it is not hardware attestation. Endpoint queue and network-recovery state are held by each endpoint and are not reported here.',
        ),
      ),
      panel(
        'Exchange activity',
        'Latest 30 of at most 1,000 returned object summaries. Protected message content and recipient key material are not included.',
        table(
          ['Object', 'State / reason', 'Priority', 'Mission', 'Sender', 'Recipient'],
          [...objects]
            .sort((a, b) => b.createdAt - a.createdAt)
            .slice(0, 30)
            .map((o) => [
              (o.id || o.objectId || '').slice(0, 18),
              el('div', {}, badge(o.state), o.reason ? hint(o.reason) : null),
              o.messagePriority || 'Legacy v1',
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
            assignedRole.setAttribute('aria-label', `Generic role for ${u.username}`);
            const assignedDuty = select(dutyChoices, u.dutyRole || '');
            assignedDuty.setAttribute('aria-label', `Duty position for ${u.username}`);
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
                      'Apply roles',
                      action(async () => {
                        if (u.dutyRole && !assignedDuty.value)
                          throw new Error(
                            'An assigned duty-position restriction cannot be removed. Select a compatible duty position.',
                          );
                        await adminMutation(`/api/admin/users/${u.id}`, 'PATCH', {
                          role: assignedRole.value,
                          ...(assignedDuty.value ? { dutyRole: assignedDuty.value } : {}),
                        });
                        notify('Role and duty-position selections saved atomically.');
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
        { className: '�~���$z{-���jםon, signed enrollment, pre-approval rejection, administrator approval and binding',
  );
  return { page, context };
}

async function checkRoleTransition(admin, auditor) {
  await admin.page.getByRole('button', { name: 'Units & users', exact: true }).click();
  const generic = admin.page.getByLabel('Generic role for bravo', { exact: true });
  const duty = admin.page.getByLabel('Duty position for bravo', { exact: true });
  const row = admin.page.getByRole('row').filter({ has: generic });
  const apply = async () => {
    const button = await row
      .getByRole('button', { name: 'Apply roles', exact: true })
      .elementHandle();
    await button.click();
    await button.waitForElementState('hidden');
    await admin.page.locator('#notice').filter({ hasText: 'saved atomically' }).waitFor();
  };
  await duty.selectOption('FIELD_OPERATOR');
  await apply();
  await generic.selectOption('auditor');
  await duty.selectOption('AUDIT_OFFICER');
  const mutation = admin.page.waitForRequest(
    (request) => request.method() === 'PATCH' && request.url().includes('/api/admin/users/'),
  );
  await apply();
  const request = await mutation;
  assert.equal(request.postDataJSON().role, 'auditor');
  assert.equal(request.postDataJSON().dutyRole, 'AUDIT_OFFICER');
  await admin.page.locator('#notice').filter({ hasText: 'saved atomically' }).waitFor();
  // Re-read authority data so selected options alone cannot satisfy this assertion.
  const refresh = await admin.page
    .getByRole('button', { name: 'Refresh console', exact: true })
    .elementHandle();
  await refresh.click();
  await refresh.waitForElementState('hidden');
  await generic.filter({ has: admin.page.locator('option[value="auditor"]:checked') }).waitFor();
  assert.equal(await generic.inputValue(), 'auditor');
  assert.equal(await duty.inputValue(), 'AUDIT_OFFICER');
  await auditor.page.getByRole('button', { name: 'Refresh authority', exact: true }).click();
  await auditor.page.getByRole('button', { name: 'Administration', exact: true }).click();
  await auditor.page.getByText('Release and security observations', { exact: true }).waitFor();
  await auditor.page.getByRole('button', { name: 'Units & users', exact: true }).click();
  assert.equal(
    await auditor.page.getByRole('button', { name: 'Apply roles', exact: true }).count(),
    0,
  );
  assert.equal(
    await auditor.page
      .getByRole('button', { name: 'Create user & MFA enrollment', exact: true })
      .count(),
    0,
  );
  results.push(
    'Administrator atomically changes operator/FIELD_OPERATOR to auditor/AUDIT_OFFICER; refreshed authority confirms both and auditor UI remains read-only',
  );
  await auditor.page.getByRole('button', { name: 'Evidence & integration', exact: true }).click();
  await auditor.context.route(
    '**/api/evidence/checkpoint',
    async (route) => {
      const response = await route.fetch();
      const checkpoint = await response.json();
      checkpoint.payload.sequence++;
      await route.fulfill({ response, json: checkpoint });
    },
    { times: 1 },
  );
  await auditor.page.getByRole('button', { name: 'Save external checkpoint', exact: true }).click();
  await auditor.page
    .locator('#notice')
    .filter({ hasText: 'signature could not be verified' })
    .waitFor();
  assert.equal(
    await auditor.page
      .getByText('No checkpoint signature checked in this view.', { exact: true })
      .count(),
    1,
  );
  const checkpointDownload = auditor.page.waitForEvent('download');
  await auditor.page.getByRole('button', { name: 'Save external checkpoint', exact: true }).click();
  await checkpointDownload;
  await auditor.page
    .getByText(/^Checkpoint signature verified with the pinned authority key:/)
    .waitFor();
  results.push(
    'Read-only auditor rejects a tampered checkpoint and displays verified status only after a valid signature check',
  );
  await auditor.context.close();
}

async function checkConcurrentVaultLocks(owner) {
  const peer = await owner.context.newPage();
  await peer.goto(base.href);
  const key = 'siepmu.browser-lock-regression';
  await owner.page.evaluate((name) => localStorage.removeItem(name), key);
  const attempt = (page, value) =>
    page.evaluate(
      async ({ key, value }) => {
        const { commitEncryptedVaultLocked } = await import('/apps/unit-client/vault-store.mjs');
        try {
          await commitEncryptedVaultLocked(localStorage, navigator.locks, key, null, {
            ciphertext: value,
          });
          return 'committed';
        } catch (error) {
          if (error.message.includes('another tab')) return 'stale';
          throw error;
        }
      },
      { key, value },
    );
  const outcomes = await Promise.all([
    attempt(owner.page, 'first-sealed-fixture'),
    attempt(peer, 'second-sealed-fixture'),
  ]);
  assert.deepEqual(outcomes.sort(), ['committed', 'stale']);
  await owner.page.evaluate((name) => localStorage.removeItem(name), key);
  await peer.close();
  results.push(
    'Actual browser Web Locks serialize two tabs and reject the stale encrypted-vault write',
  );
}

async function exchangeFile(alice, bob) {
  await alice.page.getByRole('button', { name: 'Secure exchange', exact: true }).click();
  const recipient = provisioning.profiles.find((p) => p.username === 'bob');
  await alice.page.getByLabel('Recipient device').selectOption(recipient.deviceId);
  let submitted = 0;
  const countSubmission = (request) => {
    if (request.method() === 'POST' && request.url().endsWith('/api/objects')) submitted++;
  };
  alice.page.on('request', countSubmission);
  await alice.page.getByLabel('Attach a file').setInputFiles({
    name: '..',
    mimeType: 'text/html',
    buffer: Buffer.from('<script>syntheticUnsafeName</script>'),
  });
  await alice.page.getByRole('button', { name: 'Seal & submit securely', exact: true }).click();
  await alice.page.locator('#notice').filter({ hasText: 'Unsafe file name' }).waitFor();
  assert.equal(submitted, 0, 'Unsafe filename must fail before any object submission');
  results.push('Unsafe dot-dot file name rejected in browser before object submission');

  const filename = 'synthetic-evidence.txt';
  const bytes = Buffer.from(
    'SIEPMU synthetic UTF-8 file\nIntegrity check: தமிழ் · हिन्दी · Δ\n',
    'utf8',
  );
  // An untrusted MIME hint is intentionally supplied; the client must treat it as opaque binary.
  await alice.page
    .getByLabel('Attach a file')
    .setInputFiles({ name: filename, mimeType: 'text/html', buffer: bytes });
  await alice.page.getByRole('button', { name: 'Seal & submit securely', exact: true }).click();
  await alice.page.locator('.badge.ready').waitFor();
  await bob.page.getByRole('button', { name: 'Refresh objects', exact: true }).click();
  await bob.page.getByRole('button', { name: 'Validate release & decrypt', exact: true }).click();
  await bob.page.locator('.object-body').filter({ hasText: filename }).waitFor();
  await bob.page.evaluate(() => {
    const original = URL.createObjectURL;
    URL.createObjectURL = function (blob) {
      globalThis.__siepmuDownloadMime = blob.type;
      return original.call(this, blob);
    };
  });
  const received = bob.page.waitForEvent('download');
  await bob.page
    .getByRole('button', { name: 'Download encrypted-transfer attachment', exact: true })
    .click();
  const download = await received;
  assert.equal(download.suggestedFilename(), filename);
  const stream = await download.createReadStream();
  const chunks = [];
  for await (const chunk of stream) chunks.push(chunk);
  assert.deepEqual(Buffer.concat(chunks), bytes);
  assert.equal(
    await bob.page.evaluate(() => globalThis.__siepmuDownloadMime),
    'application/octet-stream',
  );
  alice.page.off('request', countSubmission);
  results.push(
    'Real file-input encryption, recipient release/decryption and attachment download preserve exact UTF-8 bytes and filename',
  );
  results.push(
    'Untrusted HTML MIME hint is replaced by application/octet-stream for attachment download',
  );
}

try {
  await checkShellUpgrades(browser, results);
  await checkTrustStorageRecovery();
  const alice = await loginUser('alice');
  const bob = await loginUser('bob');
  const admin = await loginUser('admin');
  results.push('MFA, encrypted provisioning vault and device binding through real browser UI');
  const bravo = await enrollFreshDevice(admin);
  await checkRoleTransition(admin, bravo);
  await checkConcurrentVaultLocks(alice);
  const message = `Synthetic browser exchange ${Date.now()} <img src=x onerror="globalThis.__siepmuXss=1">`;
  await createMessage(alice.page, message);
  await alice.page.locator('.badge.ready').waitFor();
  await bob.page.getByRole('button', { name: 'Objects & receipts', exact: true }).click();
  await bob.page.getByRole('button', { name: 'Refresh objects', exact: true }).click();
  await bob.page.getByRole('button', { name: 'Validate release & decrypt', exact: true }).click();
  await bob.page.getByText(message, { exact: true }).waitFor();
  assert.equal(await bob.page.evaluate(() => globalThis.__siepmuXss), undefined);
  assert.equal(await bob.page.locator('.object-body img').count(), 0);
  results.push(
    'End-to-end text encryption, release, browser decryption, ACK and untrusted text rendering',
  );
  await exchangeFile(alice, bob);

  await alice.page.getByRole('button', { name: 'Simulate disconnect', exact: true }).click();
  const queuedMessage = `Queued during authority change ${Date.now()}`;
  await createMessage(alice.page, queuedMessage);
  await alice.page.locator('.badge.queued').waitFor();
  await setPolicy(admin.page, false);
  await alice.page.getByRole('button', { name: 'Reconnect & validate', exact: true }).click();
  await alice.page.locator('.badge.held').first().waitFor();
  results.push(
    'Durable local queue and current-policy hold after simulated disconnect/reconnection',
  );
  await setPolicy(admin.page, true);
  await alice.page
    .getByRole('button', { name: 'Synchronize eligible objects', exact: true })
    .click();
  await alice.page.locator('.badge.ready').waitFor();
  await bob.page.getByRole('button', { name: 'Refresh objects', exact: true }).click();
  await bob.page.getByRole('button', { name: 'Validate release & decrypt', exact: true }).click();
  await bob.page.getByText(queuedMessage, { exact: true }).waitFor();
  results.push('Permitted current-policy release after explicit authority change');

  const stored = await alice.page.evaluate(() =>
    JSON.stringify(Object.fromEntries(Object.entries(localStorage))),
  );
  assert.ok(!stored.includes(message), 'Plaintext message must not appear in localStorage');
  assert.ok(
    !stored.includes(alice.profile.keys.signing.privateKey.d),
    'Private key must not appear in localStorage',
  );
  assert.ok(
    !stored.includes(alice.profile.password),
    'Login password must not appear in localStorage',
  );
  assert.ok(
    !stored.includes(alice.profile.totpSecret),
    'TOTP seed must not appear in localStorage',
  );
  results.push(
    'Encrypted local persistence and no stored bootstrap credentials/private key plaintext',
  );

  await alice.page.evaluate(() => navigator.serviceWorker.ready);
  await alice.context.setOffline(true);
  await alice.page.reload({ waitUntil: 'domcontentloaded' });
  await alice.page.getByLabel('Vault username', { exact: true }).fill('alice');
  await alice.page.getByLabel('Vault passphrase', { exact: true }).fill(vaultSecret);
  await alice.page.getByRole('button', { name: 'Unlock encrypted vault', exact: true }).click();
  await alice.page.locator('#identity').filter({ hasText: 'offline grant only' }).waitFor();
  await createMessage(alice.page, `Offline browser-restart queue ${Date.now()}`);
  await alice.page.locator('.badge.queued').waitFor();
  results.push(
    'Real browser offline reload, encrypted vault unlock and bounded local queue creation',
  );
  await alice.context.setOffline(false);
  await alice.page.getByRole('button', { name: 'Reconnect & validate', exact: true }).click();
  await alice.page.getByRole('button', { name: 'Authenticate with MFA', exact: true }).waitFor();
  results.push('Fresh MFA required before post-reload server reconnection');

  await bob.page.screenshot({ path: resolve(artifactDir, 'recipient.png'), fullPage: true });
  await admin.page.screenshot({ path: resolve(artifactDir, 'authority.png'), fullPage: true });
  assert.deepEqual(errors, [], 'No uncaught browser runtime errors');
  console.log(
    JSON.stringify({ status: 'PASS', browser: browser.version(), assertions: results }, null, 2),
  );
} catch (error) {
  let index = 0;
  for (const context of browser.contexts()) {
    for (const page of context.pages()) {
      await page
        .screenshot({ path: resolve(artifactDir, `failure-${index++}.png`), fullPage: true })
        .catch(() => {});
    }
  }
  console.error(
    JSON.stringify(
      { status: 'FAIL', assertionsCompleted: results, browserErrors: errors, error: error.message },
      null,
      2,
    ),
  );
  throw error;
} finally {
  await browser.close();
}
