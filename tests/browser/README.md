# Browser upgrade regression

`checkShellUpgrades` runs through `npm run test:browser:isolated` and uses a disposable
loopback HTTP server and an actual Chromium context. It interrupts a dependency transfer,
checks offline schema-v2 encryption/decryption, tests installation/activation sequencing,
and verifies that API responses never enter the shell cache.

The two text fixtures freeze public source from repository commit
`40ab9d038cd521e29ebd57b5e7dde041f9c61212`: the legacy network-first service worker and
its canonical module. The harness app is synthetic; encryption and decryption run the
current real crypto implementation against the cached historical canonical module.
The main browser acceptance runner separately exercises the actual application UI.

The new worker uses an immutable cache generation and waits for existing clients to close.
After a completed deployment, close all existing tabs and reopen to activate the new shell.
Each release that changes any shell asset must bump its cache generation and deploy the
complete release directory atomically. A failed installation leaves the previous complete
cache available. Browsers may evict offline storage; an evicted shell requires reconnection.
This test does not claim fault tolerance against browser storage eviction or a server
that serves mutually inconsistent asset versions during a non-atomic deployment.
