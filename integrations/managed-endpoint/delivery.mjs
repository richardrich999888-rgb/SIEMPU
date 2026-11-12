const fail = (code) => Object.assign(new Error(code), { code });

// One explicit attempt, through the normal authenticated authority path. Never cache a
// success, reuse a device proof, retry a key release, or erase an ambiguous submission.
export async function submitFromOutbox(endpoint, store, objectId) {
  const item = store.get(objectId);
  if (!item || !['PENDING', 'SUBMITTED'].includes(item.state)) throw fail('OUTBOX_STATE');
  if (item.sealed.envelope.expiresAt <= Date.now()) {
    store.update(objectId, 'HELD', 'EXPIRED_OBJECT');
    throw fail('EXPIRED_OBJECT');
  }
  const result = await endpoint.submit(item.sealed);
  // IntegrationEndpoint verifies the signed receipt before returning. A lost response,
  // policy refusal, or local storage failure leaves the same sealed object recoverable.
  store.update(objectId, 'SUBMITTED');
  return result;
}

export async function sendWithOutbox(endpoint, store, recipient, payload, options) {
  const sealed = await endpoint.seal(recipient, payload, options);
  const objectId = store.enqueue(sealed);
  return submitFromOutbox(endpoint, store, objectId);
}
