import {
  generateDeviceKeys,
  sign,
  verifyPacket,
  keyId,
  sha256,
  encryptObject,
  decryptObject,
  sealVault,
  openVault,
  createTextPayload,
  createFilePayload,
  unpackPayload,
} from '/packages/crypto/crypto.mjs';
import { canonical } from '/packages/protocol/canonical.mjs';
import { element as el, field, button, badge, hint, panel, download, safeName } from './dom.mjs';
import { renderAdmin } from '/apps/admin-console/admin.mjs';
import { commitEncryptedVault } from './vault-store.mjs';

const VAULT_PREFIX = 'siepmu.vault.v1.';
const PIN_KEY = 'siepmu.authority.pin.v1';
const META_KEY = 'siepmu.public-meta.v1';
const state = {
  meta: null,
  pin: null,
  token: null,
  user: null,
  device: null,
  vault: null,
  vaultStored: null,
  passphrase: null,
  offline: false,
  online: false,
  localOnly: false,
  view: location.pathname.startsWith('/admin') ? 'admin' : 'exchange',
  objects: [],
  admin: null,
  save: Promise.resolve(),
};
const main = document.querySelector('#main');

function notify(message, error = false) {
  const node = document.querySelector('#notice');
  node.textContent = message;
  node.className = error ? 'error' : '';
  node.hidden = false;
}
function action(fn) {
  return async (event) => {
    event?.preventDefault();
    const source = event?.currentTarget;
    if (source?.tagName === 'BUTTON') source.disabled = true;
    try {
      await fn(event);
    } catch (error) {
      if (error.status === 401 && state.token) {
        state.token = null;
        state.user = null;
        state.device = null;
        state.localOnly = false;
        await render();
      }
      notify(error.message || 'The operation was not completed.', true);
    } finally {
      if (source?.tagName === 'BUTTON') source.disabled = false;
      updateStatus();
    }
  };
}
async function api(path, method = 'GET', body) {
  if (state.offline)
    throw new Error(
      'Transport is disconnected by the demonstrator. Local encrypted work remains available.',
    );
  const headers = { Accept: 'application/json' };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  let response;
  try {
    response = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'omit',
      cache: 'no-store',
      signal: AbortSignal.timeout(20000),
    });
    state.online = true;
  } catch (error) {
    state.online = false;
    updateStatus();
    throw new Error(
      `Authority unavailable; your encrypted queue is retained. ${error.name === 'TimeoutError' ? 'Request timed out.' : ''}`,
    );
  }
  const result = await response.json().catch(() => ({ error: 'Invalid authority response' }));
  if (!response.ok) {
    const error = new Error(
      `${result.code || response.status}: ${result.error || 'Request rejected'}`,
    );
    error.result = result;
    error.status = response.status;
    throw error;
  }
  return result;
}
function requirePin() {
  if (!state.pin || !state.meta || canonical(state.pin) !== canonical(state.meta.serverPublicKey))
    throw new Error(
      'The authority signing key is not trusted. Import a trusted profile or confirm its fingerprint first.',
    );
}
async function verified(packet, label) {
  requirePin();
  if (!(await verifyPacket(state.pin, packet)))
    throw new Error(`${label} signature could not be verified.`);
  return packet.payload;
}
async function persist() {
  if (!state.vault || !state.passphrase)
    throw new Error('Unlock an encrypted endpoint vault first.');
  const snapshot = JSON.parse(JSON.stringify(state.vault));
  const secret = state.passphrase;
  const key = `${VAULT_PREFIX}${snapshot.username}`;
  state.save = state.save
    .catch(() => {})
    .then(async () => {
      const previous = state.vaultStored;
      const packet = await sealVault(snapshot, secret);
      state.vaultStored = commitEncryptedVault(localStorage, key, previous, packet);
    });
  return state.save;
}
async function proof(operation, body = {}) {
  if (!state.device || !state.vault)
    throw new Error('Bind an approved device before this operation.');
  const challenge = await api('/api/auth/challenge', 'POST', {
    purpose: 'operation',
    deviceId: state.device.id,
    operation,
    requestHash: await sha256(canonical(body)),
  });
  return {
    challengeId: challenge.challengeId,
    signature: await sign(state.vault.keys.signing.privateKey, challenge.challenge),
  };
}
async function adminMutation(path, method, body = {}) {
  return api(path, method, { ...body, proof: await proof(`admin:${method}:${path}`, body) });
}
async function bindDevice() {
  if (!state.token || !state.vault?.deviceId) return;
  if (state.user.username !== state.vault.username)
    throw new Error(
      'The unlocked vault belongs to a different username. Lock it before switching accounts.',
    );
  const challenge = await api('/api/auth/challenge', 'POST', {
    purpose: 'bind',
    deviceId: state.vault.deviceId,
  });
  const result = await api('/api/auth/bind', 'POST', {
    deviceId: state.vault.deviceId,
    challengeId: challenge.challengeId,
    signature: await sign(state.vault.keys.signing.privateKey, challenge.challenge),
  });
  state.device = result.device;
  await refreshAuthority();
}
async function refreshAuthority() {
  requirePin();
  const identity = await api('/api/auth/me');
  state.user = identity.user;
  state.device = identity.device;
  const controlPacket = await api('/api/control');
  const control = await verified(controlPacket, 'Control snapshot');
  if (control.expiresAt <= Date.now()) throw new Error('The signed control snapshot has expired.');
  if (state.vault?.control && control.epoch < state.vault.control.payload.epoch)
    throw new Error('Authority epoch rollback detected. Stop and investigate.');
  const directory = await api('/api/directory');
  const signedDirectory = await verified(directory.packet, 'Device directory');
  if (
    canonical(signedDirectory.users) !== canonical(directory.users) ||
    canonical(signedDirectory.devices) !== canonical(directory.devices)
  )
    throw new Error('The device directory differs from its signed snapshot.');
  if (signedDirectory.expiresAt && signedDirectory.expiresAt <= Date.now())
    throw new Error('The signed device directory has expired.');
  if (state.vault) {
    state.vault.user = state.user;
    state.vault.device = state.device;
    state.vault.control = controlPacket;
    state.vault.directory = directory;
    state.vault.clockFloor = Math.max(state.vault.clockFloor || 0, Date.now(), control.issuedAt);
    if (state.device && state.user.role === 'operator') {
      const grant = await api('/api/grants', 'POST', { proof: await proof('grant') });
      await verified(grant, 'Creation grant');
      state.vault.grant = grant;
    } else delete state.vault.grant;
    await persist();
  }
  const result = await api('/api/objects');
  state.objects = result.objects;
  updateStatus();
}
function updateStatus() {
  const connection = document.querySelector('#connection');
  connection.textContent = state.offline
    ? 'Simulated disconnect'
    : state.online
      ? 'Authority reachable'
      : 'Authority unavailable';
  connection.className = `status-pill${state.offline || !state.online ? ' offline' : ''}`;
  document.querySelector('#epoch').textContent =
    `Authority epoch ${state.vault?.control?.payload.epoch ?? '—'}${state.offline ? ' · cached' : ''}`;
  document.querySelector('#device-status').textContent = state.device
    ? `Device ${state.device.label || state.device.id.slice(0, 8)} · bound`
    : state.vault?.deviceId
      ? 'Device loaded · unbound'
      : 'Device unbound';
  document.querySelector('#identity').textContent = state.user
    ? `${state.user.username} · ${state.localOnly ? 'offline grant only' : state.user.role}`
    : 'No active session';
  document.querySelector('#lock-button').hidden = !state.token && !state.vault;
  document.querySelector('#transport-toggle').disabled = !state.vault;
  document.querySelector('#transport-toggle').textContent =
    state.offline || state.localOnly || !state.online
      ? 'Reconnect & validate'
      : 'Simulate disconnect';
  document.querySelector('#refresh-button').disabled = !state.token || state.offline;
}
function renderNav() {
  const items = [
    ['exchange', 'Secure exchange'],
    ['objects', 'Objects & receipts'],
    ['vault', 'Endpoint vault'],
  ];
  if (!state.localOnly && ['admin', 'auditor'].includes(state.user?.role))
    items.push(['admin', 'Administration']);
  document.querySelector('#navigation').replaceChildren(
    ...items.map(([view, label]) =>
      button(
        label,
        action(async () => {
          state.view = view;
          await render();
        }),
        state.view === view ? 'active' : '',
      ),
    ),
  );
}
async function render() {
  updateStatus();
  renderNav();
  document.querySelector('#page-title').textContent = {
    exchange: 'Unit workspace',
    objects: 'Objects & receipts',
    vault: 'Endpoint vault',
    admin: 'Authority console',
  }[state.view];
  if (!state.meta) {
    main.replaceChildren(
      panel(
        'Authority unavailable',
        'Start the three services, then retry.',
        button('Retry connection', action(initialize)),
      ),
    );
    return;
  }
  if (!state.pin || canonical(state.pin) !== canonical(state.meta.serverPublicKey)) {
    renderTrust();
    return;
  }
  if ((!state.token && !state.localOnly) || !state.vault) {
    renderAccess();
    return;
  }
  if (state.view === 'vault' || !state.device) {
    renderVault();
    return;
  }
  if (state.view === 'admin' && !state.localOnly) {
    main.replaceChildren(
      panel(
        'Loading authority console',
        'Fetching current identities, policy and security events.',
      ),
    );
    await renderAdmin(main, {
      api,
      adminMutation,
      action,
      notify,
      state,
      verified,
      refreshAuthority,
      render,
      download,
    });
  } else if (state.view === 'objects') renderObjects();
  else renderExchange();
}
function renderTrust() {
  const mismatch = Boolean(state.pin);
  const fingerprint = el(
    'p',
    { className: 'fingerprint' },
    state.meta.serverKeyId || 'Loading fingerprint',
  );
  const node = panel(
    mismatch ? 'Authority key changed' : 'Establish authority trust',
    mismatch
      ? 'The server key differs from your locally retained pin. Verify the change through an independent trusted channel.'
      : 'Import your provisioned demo profile, or independently verify the authority fingerprint before first use.',
    el('span', { className: 'pill-label' }, 'AUTHORITY PUBLIC-KEY FINGERPRINT'),
    fingerprint,
    el(
      'div',
      { className: 'warning' },
      'Trust on first use does not protect against a compromised first connection or modified client software.',
    ),
    el(
      'div',
      { className: 'form-actions' },
      button(
        mismatch
          ? 'Accept independently verified replacement'
          : 'Trust independently verified authority',
        action(async () => {
          state.pin = state.meta.serverPublicKey;
          localStorage.setItem(PIN_KEY, JSON.stringify(state.pin));
          notify('Authority public key pinned on this browser.');
          await render();
        }),
      ),
    ),
    importPanel(),
  );
  node.classList.add('trust-card');
  main.replaceChildren(node);
}
function importPanel() {
  const input = el('input', {
    type: 'file',
    accept: '.json,application/json',
    'aria-label': 'Provisioning profile file',
  });
  const choices = el('select', { 'aria-label': 'Profile username', disabled: true });
  const pass = el('input', {
    type: 'password',
    minLength: 12,
    autoComplete: 'new-password',
    placeholder: 'At least 12 characters',
  });
  let profiles;
  let trustedKey;
  input.addEventListener(
    'change',
    action(async () => {
      if (!input.files[0]) return;
      if (input.files[0].size > 1024 * 1024) throw new Error('Provisioning file is too large.');
      const data = JSON.parse(await input.files[0].text());
      if (!Array.isArray(data.profiles) || !data.serverPublicKey)
        throw new Error('Expected a generated demo-profiles.json provisioning file.');
      profiles = data.profiles;
      trustedKey = data.serverPublicKey;
      choices.replaceChildren(
        ...profiles.map((p, i) => el('option', { value: String(i) }, p.username)),
      );
      choices.disabled = false;
    }),
  );
  return el(
    'details',
    {},
    el('summary', {}, 'Import a provisioned synthetic demo device'),
    hint(
      'Choose one profile. Its device keys will be encrypted with your vault passphrase. Bootstrap passwords and TOTP seeds are not saved by this app.',
    ),
    el(
      'div',
      { className: 'form-stack' },
      field('Provisioning file', input),
      field('Profile', choices),
      field('New vault passphrase', pass),
      button(
        'Import & encrypt selected profile',
        action(async () => {
          if (!profiles || !profiles[choices.value])
            throw new Error('Select a provisioning profile first.');
          const p = profiles[choices.value];
          if (
            !p.username ||
            !p.deviceId ||
            !p.keys?.signing?.privateKey ||
            !p.keys?.encryption?.privateKey
          )
            throw new Error('The selected profile has no complete device key pair.');
          if (pass.value.length < 12)
            throw new Error('Use a vault passphrase of at least 12 characters.');
          if (state.meta && canonical(trustedKey) !== canonical(state.meta.serverPublicKey))
            throw new Error('Provisioned authority key does not match this server.');
          if (state.token && state.user.username !== p.username)
            throw new Error('Sign out before importing a different user’s profile.');
          const existing = localStorage.getItem(`${VAULT_PREFIX}${p.username}`);
          if (existing)
            throw new Error(
              'A vault already exists for this username. Unlock or explicitly remove it before importing again.',
            );
          state.pin = trustedKey;
          localStorage.setItem(PIN_KEY, JSON.stringify(trustedKey));
          state.passphrase = pass.value;
          state.vaultStored = null;
          state.vault = {
            version: 1,
            username: p.username,
            deviceId: p.deviceId,
            keys: p.keys,
            outbox: [],
            inbox: [],
            clockFloor: Date.now(),
          };
          await persist();
          profiles = null;
          trustedKey = null;
          input.value = '';
          pass.value = '';
          notify(
            `Device imported for ${p.username}. Sign in using the separately provisioned password and current TOTP.`,
          );
          if (state.token) await bindDevice();
          await render();
        }),
      ),
    ),
  );
}
function renderAccess() {
  const username = el('input', {
    name: 'username',
    autoComplete: 'username',
    required: true,
    value: state.vault?.username || '',
  });
  const password = el('input', {
    name: 'password',
    type: 'password',
    autoComplete: 'current-password',
    required: true,
  });
  const otp = el('input', {
    name: 'otp',
    inputMode: 'numeric',
    pattern: '[0-9]{6}',
    maxLength: 6,
    autoComplete: 'one-time-code',
    required: true,
    placeholder: '6-digit authenticator code',
  });
  const login = el(
    'form',
    {
      className: 'form-stack',
      onSubmit: action(async () => {
        requirePin();
        if (state.vault && state.vault.username !== username.value.trim())
          throw new Error('The unlocked vault belongs to another user. Lock it first.');
        const result = await api('/api/auth/login', 'POST', {
          username: username.value.trim(),
          password: password.value,
          otp: otp.value,
        });
        state.token = result.token;
        state.user = result.user;
        state.localOnly = false;
        password.value = '';
        otp.value = '';
        notify('Password and MFA accepted. Device-bound operations require the matching vault.');
        try {
          await bindDevice();
        } finally {
          await render();
        }
      }),
    },
    field('Username', username),
    field('Password', password),
    field('Authenticator code', otp),
    el('button', { type: 'submit' }, 'Authenticate with MFA'),
  );
  const vaultUser = el('input', {
    value: state.user?.username || state.vault?.username || '',
    autoComplete: 'username',
  });
  const pass = el('input', { type: 'password', minLength: 12, autoComplete: 'current-password' });
  const vaultForm = el(
    'form',
    {
      className: 'form-stack',
      onSubmit: action(async () => {
        const name = vaultUser.value.trim();
        const encrypted = localStorage.getItem(`${VAULT_PREFIX}${name}`);
        if (!encrypted)
          throw new Error(
            'No encrypted vault exists for this username. Import a profile or create a vault below.',
          );
        const vault = await openVault(JSON.parse(encrypted), pass.value);
        if (vault.username !== name) throw new Error('Vault identity mismatch.');
        if (state.user && state.user.username !== name)
          throw new Error('Sign out before unlocking another user’s vault.');
        state.vault = vault;
        state.vaultStored = encrypted;
        state.passphrase = pass.value;
        pass.value = '';
        if (!state.online && vault.user && vault.device) {
          state.user = vault.user;
          state.device = vault.device;
          state.localOnly = true;
          state.view = 'exchange';
          notify(
            'Offline vault unlocked. Only cached-grant local operations are available; reconnect requires fresh MFA authentication.',
          );
          await render();
          return;
        }
        notify('Endpoint vault unlocked in this tab.');
        try {
          await bindDevice();
        } finally {
          await render();
        }
      }),
    },
    field('Vault username', vaultUser),
    field('Vault passphrase', pass),
    el('button', { type: 'submit' }, 'Unlock encrypted vault'),
    button(
      'Create a new device vault',
      action(async () => {
        const name = vaultUser.value.trim();
        if (!/^[A-Za-z0-9_.@-]{1,100}$/.test(name))
          throw new Error('Enter a valid username for the new vault.');
        if (state.user && state.user.username !== name)
          throw new Error('New vault username must match the active session.');
        if (localStorage.getItem(`${VAULT_PREFIX}${name}`))
          throw new Error('A vault already exists. Unlock it instead.');
        if (pass.value.length < 12)
          throw new Error('Use a vault passphrase of at least 12 characters.');
        state.vault = {
          version: 1,
          username: name,
          deviceId: null,
          keys: await generateDeviceKeys(),
          outbox: [],
          inbox: [],
          clockFloor: Date.now(),
        };
        state.vaultStored = null;
        state.passphrase = pass.value;
        pass.value = '';
        await persist();
        notify('New device keys generated and encrypted. Authenticate, then enroll this device.');
        await render();
      }),
      'quiet',
    ),
  );
  const intro = el(
    'div',
    { className: 'login-intro' },
    el('h2', {}, 'Authenticate the person. Bind the device.'),
    hint(
      'End-to-end encrypted exchange with current-policy admission. Your session stays in tab memory; your device keys and queued objects stay in an encrypted local vault.',
    ),
  );
  main.replaceChildren(
    intro,
    el(
      'div',
      { className: 'grid' },
      panel(
        '01 · Identity',
        state.token
          ? `Authenticated as ${state.user.username}.`
          : 'Password plus mandatory time-based second factor.',
        state.token ? badge('Authenticated') : login,
      ),
      panel(
        '02 · Endpoint vault',
        state.vault
          ? `Unlocked for ${state.vault.username}.`
          : 'Separate vault passphrase protects stored device keys and local work.',
        state.vault
          ? el(
              'div',
              {},
              badge('Unlocked'),
              hint('Complete identity authentication to bind this device.'),
            )
          : vaultForm,
        importPanel(),
      ),
    ),
  );
}
function renderVault() {
  const v = state.vault;
  const label = el('input', { value: `${v.username} browser device`, maxLength: 80 });
  main.replaceChildren(
    el(
      'div',
      { className: 'grid' },
      panel(
        'Device binding',
        'Software key possession is demonstrated. Hardware attestation is not implemented.',
        el('p', { className: 'object-id' }, v.deviceId || 'Not yet enrolled'),
        badge(state.device ? 'Approved' : 'Unbound'),
        field('Enrollment label', label),
        el(
          'div',
          { className: 'form-actions' },
          button(
            v.deviceId ? 'Bind existing device' : 'Enroll device',
            action(async () => {
              if (v.deviceId) await bindDevice();
              else {
                const challenge = await api('/api/auth/challenge', 'POST', { purpose: 'enroll' });
                const result = await api('/api/devices/enroll', 'POST', {
                  label: label.value,
                  signingPublicKey: v.keys.signing.publicKey,
                  encryptionPublicKey: v.keys.encryption.publicKey,
                  challengeId: challenge.challengeId,
                  signature: await sign(v.keys.signing.privateKey, challenge.challenge),
                });
                v.deviceId = result.device.id;
                await persist();
                notify(
                  'Device enrolled. An approved administrator must authorize it before binding.',
                );
              }
              await render();
            }),
          ),
          button(
            'Go to exchange',
            action(async () => {
              state.view = 'exchange';
              await render();
            }),
            'quiet',
          ),
        ),
        el(
          'details',
          {},
          el('summary', {}, 'Inspect public device keys'),
          el(
            'pre',
            {},
            JSON.stringify(
              { signing: v.keys.signing.publicKey, encryption: v.keys.encryption.publicKey },
              null,
              2,
            ),
          ),
        ),
      ),
      panel(
        'Encrypted local storage',
        'Vault exports contain encrypted keys, queue, cached policy and received content. Keep the passphrase separately.',
        el('p', {}, `${v.outbox.length} local outbox objects · ${v.inbox.length} received objects`),
        button(
          'Export encrypted vault',
          action(async () => {
            download(
              await sealVault(JSON.parse(JSON.stringify(v)), state.passphrase),
              `${safeName(v.username)}-vault.encrypted.json`,
            );
          }),
        ),
        hint(
          'Private keys are available to this browser while unlocked. Modified client software or a compromised endpoint can access plaintext.',
        ),
        vaultRestorePanel(),
        el('div', { className: 'divider' }),
        button(
          'Remove local vault from this browser',
          action(async () => {
            if (
              !window.confirm(
                'Remove this encrypted vault, keys, queued objects and local inbox from this browser? Export it first if needed.',
              )
            )
              return;
            localStorage.removeItem(`${VAULT_PREFIX}${v.username}`);
            await logout();
          }),
          'danger',
        ),
      ),
    ),
  );
}
function vaultRestorePanel() {
  const file = el('input', {
    type: 'file',
    accept: '.json,application/json',
    'aria-label': 'Encrypted vault backup',
  });
  const pass = el('input', { type: 'password', autoComplete: 'current-password' });
  return el(
    'details',
    {},
    el('summary', {}, 'Restore an encrypted vault backup'),
    field('Encrypted vault JSON', file),
    field('Backup passphrase', pass),
    button(
      'Validate & restore backup',
      action(async () => {
        if (!file.files[0] || file.files[0].size > 8 * 1024 * 1024)
          throw new Error('Select an encrypted vault backup no larger than 8 MiB.');
        const packet = JSON.parse(await file.files[0].text());
        const restored = await openVault(packet, pass.value);
        if (
          !restored.keys ||
          !restored.username ||
          !Array.isArray(restored.outbox) ||
          !Array.isArray(restored.inbox)
        )
          throw new Error('Invalid vault structure.');
        if (restored.username !== state.user?.username)
          throw new Error('Backup must belong to the currently authenticated user.');
        if (
          !window.confirm(
            'Replace this local vault with the selected backup? Current local work will be replaced.',
          )
        )
          return;
        state.vault = restored;
        state.vaultStored = localStorage.getItem(`${VAULT_PREFIX}${restored.username}`);
        state.passphrase = pass.value;
        state.device = null;
        await persist();
        await bindDevice();
        notify('Vault restored and device rebound.');
        await render();
      }),
      'quiet',
    ),
  );
}
function stats() {
  const objects = state.objects || [];
  return el(
    'div',
    { className: 'stat-grid' },
    [
      ['Encrypted queue', state.vault.outbox.filter((o) => !o.submitted).length],
      ['Held by authority', objects.filter((o) => o.state === 'HELD').length],
      ['Locally received', state.vault.inbox.length],
      ['Authority epoch', state.vault.control?.payload.epoch ?? '—'],
    ].map(([label, count]) =>
      el('div', { className: 'stat' }, el('strong', {}, count), el('span', {}, label)),
    ),
  );
}
function renderExchange() {
  const directory = state.vault.directory;
  const users = directory?.users || [];
  const devices = (directory?.devices || []).filter(
    (d) =>
      (d.status === 'approved' || d.status === 'APPROVED' || d.active === true) &&
      d.id !== state.device.id,
  );
  const recipient = el(
    'select',
    { required: true, 'aria-label': 'Recipient device' },
    el('option', { value: '' }, 'Select a recipient device'),
    devices.map((d) =>
      el(
        'option',
        { value: d.id },
        `${users.find((u) => u.id === d.userId)?.username || d.userId} · ${d.label || d.id.slice(0, 8)}`,
      ),
    ),
  );
  const missions = state.user.missionIds || [];
  const mission = el(
    'select',
    { 'aria-label': 'Mission' },
    missions.map((m) => el('option', { value: m }, m)),
  );
  const text = el('textarea', {
    name: 'message',
    placeholder: 'Synthetic mission information…',
    maxLength: 20000,
  });
  const file = el('input', { type: 'file', 'aria-label': 'Attach a file' });
  const form = el(
    'form',
    {
      className: 'form-stack',
      onSubmit: action(async () => {
        if (state.user.role !== 'operator')
          throw new Error('Only an operator may originate an information object.');
        const target = devices.find((d) => d.id === recipient.value);
        const targetUser = users.find((u) => u.id === target?.userId);
        if (!target || !targetUser)
          throw new Error('Choose an approved recipient from the signed directory.');
        const now = Date.now();
        if (now + 5000 < (state.vault.clockFloor || 0))
          throw new Error(
            'Local clock rollback detected. Refresh authority before creating more work.',
          );
        const grant = state.vault.grant;
        const grantPayload = grant && (await verified(grant, 'Cached creation grant'));
        if (!grantPayload || grantPayload.expiresAt <= now)
          throw new Error(
            'Your creation grant has expired or is missing. Reconnect and refresh authority.',
          );
        let payload;
        if (file.files[0]) {
          if (file.files[0].size > 512 * 1024)
            throw new Error('This local-storage demonstrator limits files to 512 KiB.');
          const bytes = new Uint8Array(await file.files[0].arrayBuffer());
          payload = createFilePayload(
            safeName(file.files[0].name),
            'application/octet-stream',
            bytes,
          );
        } else {
          if (!text.value.trim()) throw new Error('Enter a message or select a file.');
          payload = createTextPayload(text.value);
        }
        const context = {
          schemaVersion: 1,
          objectId: crypto.randomUUID(),
          senderUserId: state.user.id,
          senderDeviceId: state.device.id,
          senderUnitId: state.user.unitId,
          recipientUserId: targetUser.id,
          recipientDeviceId: target.id,
          recipientUnitId: targetUser.unitId,
          recipientKeyId: await keyId(target.encryptionPublicKey),
          missionId: mission.value,
          classification: 'DEMO',
          action: 'deliver',
          createdAt: now,
          expiresAt: Math.min(now + 3600000, grantPayload.expiresAt),
          creationGrant: grant,
          cryptoSuite: 'P256-HKDF-SHA256-AES256GCM',
          keyVersion: 1,
        };
        const submission = await encryptObject(
          context,
          payload,
          target.encryptionPublicKey,
          state.vault.keys.signing.privateKey,
        );
        const queued = {
          submission,
          queuedAt: now,
          state: 'QUEUED',
          submitted: false,
          reason: null,
        };
        state.vault.outbox.push(queued);
        state.vault.clockFloor = Math.max(state.vault.clockFloor || 0, now);
        await persist();
        text.value = '';
        file.value = '';
        notify('Object sealed and durably saved in your encrypted local outbox.');
        if (!state.offline && !state.localOnly) {
          try {
            await submitQueued(queued);
            await refreshAuthority();
          } catch (error) {
            notify(`Object retained locally. ${error.message}`, true);
          }
        }
        renderExchange();
      }),
    },
    field('Recipient', recipient),
    field('Mission', mission),
    field('Message', text),
    field('Or attach one file', file),
    hint(
      'Files are encrypted as opaque data and downloaded as attachments. This demonstrator does not scan endpoint plaintext for malware. Maximum file size: 512 KiB.',
    ),
    el(
      'button',
      { type: 'submit', disabled: state.user.role !== 'operator' },
      state.offline || state.localOnly || !state.online
        ? 'Seal into offline queue'
        : 'Seal & submit securely',
    ),
  );
  main.replaceChildren(
    stats(),
    el(
      'div',
      { className: 'grid wide' },
      panel(
        'Create an information object',
        'A fresh content key protects every object. Current authority is checked again before recipient release.',
        form,
      ),
      panel(
        'Local outbox',
        'Queued objects survive a tab restart. Reconnection validates current authority; it does not release everything.',
        el(
          'div',
          { className: 'form-actions' },
          button('Synchronize eligible objects', action(reconnect), 'quiet'),
        ),
        outboxList(),
      ),
    ),
    panel(
      'Received information',
      'Recipient decryption happens in this browser after a signed release. Downloads are never opened automatically.',
      inboxList(),
    ),
  );
}
async function submitQueued(item) {
  const id = item.submission.envelope.objectId;
  if (!item.submitted) {
    const response = await api('/api/objects', 'POST', {
      ...item.submission,
      proof: await proof('submit', item.submission),
    });
    const admission = await verified(response.receipt, 'Admission receipt');
    if (
      admission.objectId !== id ||
      admission.details?.objectDigest !== item.submission.envelope.ciphertextHash
    )
      throw new Error('Admission receipt does not bind this object.');
    item.submitted = true;
    item.state = response.object.state;
    item.receipt = response.receipt;
    await persist();
  }
  try {
    const response = await api(`/api/objects/${id}/prepare`, 'POST', {
      proof: await proof(`prepare:${id}`),
    });
    const preparation = await verified(response.receipt, 'Preparation receipt');
    if (
      preparation.objectId !== id ||
      preparation.details?.objectDigest !== item.submission.envelope.ciphertextHash
    )
      throw new Error('Preparation receipt does not bind this object.');
    item.state = response.object.state;
    item.reason = response.object.reason || response.object.holdReason || null;
    item.receipt = response.receipt;
  } catch (error) {
    if (error.result?.object) {
      await verified(error.result.receipt, 'Held-decision receipt');
      item.state = error.result.object.state;
      item.reason = error.result.object.reason || error.result.code;
      item.receipt = error.result.receipt;
    } else {
      item.reason = error.message;
      throw error;
    }
  } finally {
    await persist();
  }
}
async function reconnect() {
  state.offline = false;
  if (!state.token) {
    state.localOnly = false;
    state.device = null;
    state.user = null;
    notify(
      'Authenticate again with MFA before reconnection can submit queued objects. Your encrypted local queue is retained.',
    );
    await render();
    return;
  }
  await refreshAuthority();
  let processed = 0;
  let failed = 0;
  for (const item of state.vault.outbox) {
    if (['DELIVERED', 'REJECTED'].includes(item.state)) continue;
    try {
      await submitQueued(item);
      processed++;
    } catch (error) {
      failed++;
      item.reason = error.message;
      await persist();
    }
  }
  await refreshAuthority();
  notify(
    `Reconnection checked ${processed} queued objects; ${failed} remain pending retry. Held objects require current policy to permit release.`,
    failed > 0,
  );
  await render();
}
function outboxList() {
  if (!state.vault.outbox.length)
    return el(
      'div',
      { className: 'empty' },
      'No locally queued objects. Create a synthetic message to begin.',
    );
  return el(
    'div',
    {},
    [...state.vault.outbox].reverse().map((item) => {
      const env = item.submission.envelope;
      const remote = state.objects.find(
        (o) => o.id === env.objectId || o.objectId === env.objectId,
      );
      return el(
        'article',
        { className: 'object-card' },
        el(
          'div',
          { className: 'object-header' },
          el('span', { className: 'object-id' }, env.objectId.slice(0, 18)),
          badge(remote?.state || item.state),
        ),
        el(
          'div',
          { className: 'object-meta' },
          `Mission ${env.missionId} · creation epoch ${env.creationGrant.payload.epoch ?? env.creationGrant.payload.creationEpoch ?? '—'}`,
        ),
        item.reason ? el('p', { className: 'warning' }, item.reason) : null,
        item.receipt
          ? button(
              'Export signed receipt',
              () => download(item.receipt, `receipt-${env.objectId}.json`),
              'quiet small',
            )
          : null,
      );
    }),
  );
}
function inboxList() {
  if (!state.vault.inbox.length)
    return el(
      'div',
      { className: 'empty' },
      'No decrypted objects in this endpoint vault. Open Objects & receipts to claim available information.',
    );
  return el(
    'div',
    {},
    [...state.vault.inbox].reverse().map((item) => {
      const content = unpackPayload(item.payload);
      return el(
        'article',
        { className: 'object-card' },
        el(
          'div',
          { className: 'object-header' },
          el('span', { className: 'object-id' }, item.objectId),
          badge('Delivered'),
        ),
        el(
          'div',
          { className: 'object-meta' },
          `Received ${new Date(item.receivedAt).toLocaleString()} · ${item.missionId}`,
        ),
        content.kind === 'text'
          ? el(
              'div',
              { className: 'object-body' },
              content.text || new TextDecoder().decode(content.bytes),
            )
          : el(
              'div',
              { className: 'object-body' },
              `${content.name} · ${content.bytes.length.toLocaleString()} bytes`,
            ),
        el(
          'div',
          { className: 'row' },
          content.kind === 'file'
            ? button(
                'Download encrypted-transfer attachment',
                () =>
                  download(
                    new Blob([content.bytes], { type: 'application/octet-stream' }),
                    safeName(content.name),
                  ),
                'quiet small',
              )
            : null,
          button(
            'Export signed release receipt',
            () => download(item.receipt, `release-${item.objectId}.json`),
            'quiet small',
          ),
        ),
      );
    }),
  );
}
async function receive(object) {
  await refreshAuthority();
  const id = object.id || object.objectId;
  let result;
  try {
    result = await api(`/api/objects/${id}/claim`, 'POST', {
      expectedEpoch: state.vault.control.payload.epoch,
      proof: await proof(`claim:${id}`, { expectedEpoch: state.vault.control.payload.epoch }),
    });
  } catch (error) {
    await refreshAuthority();
    await render();
    throw error;
  }
  const receipt = await verified(result.receipt, 'Release receipt');
  if (
    receipt.objectId !== id ||
    receipt.details?.objectDigest !== result.envelope.ciphertextHash ||
    receipt.details?.envelopeDigest !== (await sha256(canonical(result.envelope)))
  )
    throw new Error('Release receipt does not bind this envelope and ciphertext.');
  const sender = state.vault.directory.devices.find((d) => d.id === result.envelope.senderDeviceId);
  if (!sender || canonical(sender.signingPublicKey) !== canonical(result.senderSigningPublicKey))
    throw new Error('Sender key differs from the signed directory.');
  if (
    result.envelope.recipientDeviceId !== state.device.id ||
    result.envelope.recipientUserId !== state.user.id ||
    result.envelope.objectId !== id
  )
    throw new Error('Released object identity or destination does not match this device.');
  const payload = await decryptObject(
    result,
    state.vault.keys.encryption.privateKey,
    sender.signingPublicKey,
  );
  if (!state.vault.inbox.some((item) => item.objectId === id)) {
    state.vault.inbox.push({
      objectId: id,
      payload,
      receipt: result.receipt,
      missionId: result.envelope.missionId,
      receivedAt: Date.now(),
    });
    await persist();
  }
  const receiptId = receipt.eventId || receipt.receiptId || receipt.id;
  await api(`/api/objects/${id}/ack`, 'POST', {
    receiptId,
    proof: await proof(`ack:${id}`, { receiptId }),
  });
  await refreshAuthority();
  notify('Object signature verified, decrypted locally and acknowledged.');
  await render();
}
function renderObjects() {
  const cards = state.objects.map((object) => {
    const id = object.id || object.objectId;
    const recipient =
      object.recipientUserId === state.user.id && object.recipientDeviceId === state.device.id;
    return el(
      'article',
      { className: 'object-card' },
      el(
        'div',
        { className: 'object-header' },
        el('span', { className: 'object-id' }, id),
        badge(object.state),
      ),
      el(
        'p',
        { className: 'object-meta' },
        `Mission ${object.missionId || '—'} · ${recipient ? 'Incoming to this device' : 'Outgoing or another enrolled device'}`,
      ),
      object.reason || object.holdReason
        ? el('p', { className: 'warning' }, object.reason || object.holdReason)
        : null,
      el(
        'div',
        { className: 'form-actions' },
        recipient
          ? button(
              state.vault.inbox.some((i) => i.objectId === id)
                ? 'Verify retry & acknowledge'
                : 'Validate release & decrypt',
              action(() => receive(object)),
              'small',
            )
          : null,
        button(
          'Re-evaluate current authority',
          action(async () => {
            const result = await api(`/api/objects/${id}/prepare`, 'POST', {
              proof: await proof(`prepare:${id}`),
            });
            await verified(result.receipt, 'Preparation receipt');
            await refreshAuthority();
            notify(
              `${result.object.state}: ${result.object.reason || 'Current authority evaluated.'}`,
            );
            await render();
          }),
          'quiet small',
        ),
        object.receipt
          ? button(
              'Export receipt',
              () => download(object.receipt, `receipt-${id}.json`),
              'quiet small',
            )
          : null,
      ),
    );
  });
  main.replaceChildren(
    stats(),
    panel(
      'Authority object register',
      'Only sender or recipient metadata is visible here. Wrapped content keys are disclosed through the current-epoch recipient claim.',
      button(
        'Refresh objects',
        action(async () => {
          await refreshAuthority();
          await render();
        }),
        'quiet',
      ),
      cards.length
        ? cards
        : el(
            'div',
            { className: 'empty section-gap' },
            'No exchanged objects are associated with this user.',
          ),
    ),
    panel(
      'Local inbox',
      'Content below was decrypted on this endpoint and is encrypted when saved to its vault.',
      inboxList(),
    ),
  );
}
async function logout() {
  if (state.token && !state.offline) {
    try {
      await api('/api/auth/logout', 'POST', {});
    } catch {
      /* Local lock still clears the bearer. */
    }
  }
  await state.save.catch(() => {});
  state.token = null;
  state.user = null;
  state.device = null;
  state.passphrase = null;
  state.vault = null;
  state.vaultStored = null;
  state.objects = [];
  state.admin = null;
  state.offline = false;
  state.localOnly = false;
  notify(
    'Tab session and decrypted vault cleared. The server session was revoked if authority was reachable.',
  );
  await render();
}
async function initialize() {
  try {
    state.pin = JSON.parse(localStorage.getItem(PIN_KEY) || 'null');
  } catch {
    state.pin = null;
  }
  try {
    state.meta = await api('/api/meta');
    localStorage.setItem(META_KEY, JSON.stringify(state.meta));
  } catch (error) {
    try {
      state.meta = JSON.parse(localStorage.getItem(META_KEY) || 'null');
    } catch {
      state.meta = null;
    }
    notify(error.message, true);
  }
  await render();
}
document.querySelector('#lock-button').addEventListener('click', action(logout));
document.querySelector('#refresh-button').addEventListener(
  'click',
  action(async () => {
    await refreshAuthority();
    await render();
    notify('Authority, signed directory and object status refreshed.');
  }),
);
document.querySelector('#transport-toggle').addEventListener(
  'click',
  action(async () => {
    if (state.offline || state.localOnly || !state.online) await reconnect();
    else {
      state.offline = true;
      notify(
        'SIMULATION: API transport is disconnected in this tab. Encryption and durable local queuing remain active.',
      );
      await render();
    }
  }),
);
window.addEventListener('beforeunload', () => {
  state.passphrase = null;
  state.token = null;
});
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(() => {
    // Local queuing remains usable in the open tab; full offline reload needs this public shell cache.
  });
}
await initialize();
