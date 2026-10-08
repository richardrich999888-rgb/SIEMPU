# Independent services and trust boundaries

The checkpoint custodian, monitoring collector, and synthetic integration adapter are separate processes with separate databases and identity material.

The checkpoint custodian accepts only a signed authority evidence chain and authorization-state digest over mutual TLS. It retains a monotonic head and refuses a validly signed but older or forked database. The control service enters recovery quarantine when the custodian cannot establish a current lease.

The collector accepts an allowlisted signed event schema. Events contain event type, time, epoch, correlation digest and a bounded reason. It does not receive object plaintext, private keys, passwords, TOTP seeds, ciphertext or wrapped keys. Batch replay is idempotent, conflicts are rejected, retention is bounded, and acknowledgements are signed.

The adapter is an independent synthetic endpoint. It authenticates to the platform, validates a versioned request, binds the sender and destination to its own configured identities, rejects stale or duplicate requests, encrypts content through the platform provider, and stores only its own request/result record. It does not represent an IAF legacy protocol or a military network integration.
