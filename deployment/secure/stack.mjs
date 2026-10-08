/** Executable local lab topology with independent HTTPS listeners, not independent hosts. */
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { Authority } from '../../services/control/core.mjs';
import { createControlServer } from '../../services/control/server.mjs';
import { createRelayServer } from '../../services/relay/server.mjs';
import { createRelayClient } from '../../services/relay/client.mjs';
import { createWebServer } from '../../services/web/server.mjs';
import {
  secureFetch,
  secureClientOptions,
  secureServerFactory,
} from '../../packages/transport/mtls.mjs';

export async function listen(server, host = '127.0.0.1', port = 0) {
  await new Promise((accept, reject) => {
    server.once('error', reject);
    server.listen(port, host, accept);
  });
  return `https://${host}:${server.address().port}`;
}
export async function closeServer(server) {
  if (!server.listening) return;
  await new Promise((accept) => {
    server.close(accept);
    server.closeAllConnections();
  });
}
export async function startSecureStack({
  directory,
  pki,
  root = resolve('.'),
  webPort = 0,
  allowPqcLab = false,
}) {
  const { web, control, relay } = pki.identities;
  const relaySecret = await readFile(resolve(directory, 'relay.secret'));
  const servers = [];
  let authority;
  try {
    const relayServer = createRelayServer({
      database: resolve(directory, 'relay/relay.sqlite'),
      secret: relaySecret,
      serverFactory: secureServerFactory({ ...relay, allowedClientPins: [control.pin] }),
    });
    servers.push(relayServer);
    const relayUrl = await listen(relayServer);
    const relayClient = createRelayClient({
      baseUrl: relayUrl,
      secret: relaySecret,
      fetchImpl: secureFetch({ ...control, serverPin: relay.pin }),
    });
    authority = new Authority({
      allowPqcLab,
      dbPath: resolve(directory, 'control.sqlite'),
      signingKey: JSON.parse(await readFile(resolve(directory, 'server-key.json'), 'utf8')),
      masterKey: await readFile(resolve(directory, 'master.key')),
      relay: relayClient,
    });
    const controlServer = createControlServer({
      authority,
      serverFactory: secureServerFactory({ ...control, allowedClientPins: [web.pin] }),
    });
    servers.push(controlServer);
    const controlUrl = await listen(controlServer);
    const webServer = createWebServer({
      root,
      controlUrl,
      serverFactory: secureServerFactory(web, { mutual: false }),
      upstreamTls: secureClientOptions({ ...web, serverPin: control.pin }),
    });
    servers.push(webServer);
    const baseUrl = await listen(webServer, '127.0.0.1', webPort);
    return {
      baseUrl,
      controlUrl,
      relayUrl,
      authority,
      fetch: secureFetch({ ca: pki.ca, serverPin: web.pin }),
      stop: async () => {
        for (const server of servers.toReversed()) await closeServer(server);
        authority.close();
      },
    };
  } catch (error) {
    for (const server of servers.toReversed()) await closeServer(server);
    authority?.close();
    throw error;
  }
}
