import assert from 'node:assert/strict';

// Validate before any SSH request. No host discovery or trust-on-first-use.
export function validateInventory(inventory, commit) {
  assert.equal(
    inventory.authorisedSyntheticExperiment,
    true,
    'EXPLICIT_HOST_AUTHORISATION_REQUIRED',
  );
  assert.equal(inventory.sourceCommit, commit, 'SOURCE_COMMIT_MISMATCH');
  assert.deepEqual(Object.keys(inventory.nodes).sort(), ['A', 'B', 'C', 'D', 'E', 'F']);
  const names = new Set();
  for (const node of Object.values(inventory.nodes)) {
    assert.match(node.host, /^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$/);
    assert.match(node.user, /^[a-z_][a-z0-9_-]{0,31}$/);
    for (const path of [node.root, node.state]) {
      assert.match(path, /^\/[A-Za-z0-9_./-]+$/);
      assert.ok(!path.split('/').includes('..'), 'PARENT_PATH_REFUSED');
    }
    assert.ok(!names.has(node.host.toLowerCase()), 'DISTINCT_HOST_ADDRESSES_REQUIRED');
    names.add(node.host.toLowerCase());
  }
  return inventory;
}
