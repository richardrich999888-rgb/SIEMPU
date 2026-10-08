import { join } from 'node:path';
import { rm } from 'node:fs/promises';
import { provision } from '../helpers/fixture.mjs';
import { ApiClient } from '../helpers/client.mjs';
import { createLabPki } from '../../deployment/secure/lab-pki.mjs';
import { startSecureStack } from '../../deployment/secure/stack.mjs';

export function apiTransport(fetchImpl, origin) {
  return async (method, path, body, token) => {
    const response = await fetchImpl(new URL(path, origin), {
      method,
      headers: {
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    return { status: response.status, body: await response.json() };
  };
}
export async function secureFixture(t) {
  const f = await provision();
  const pki = createLabPki(join(f.dir, 'pki'));
  const stack = await startSecureStack({ directory: f.dir, pki });
  const transport = apiTransport(stack.fetch, stack.baseUrl);
  const clients = Object.fromEntries(
    Object.entries(f.profiles).map(([name, profile]) => [name, new ApiClient(transport, profile)]),
  );
  t.after(async () => {
    await stack.stop();
    await rm(f.dir, { recursive: true, force: true });
  });
  return { ...f, ...stack, pki, clients, transport };
}
