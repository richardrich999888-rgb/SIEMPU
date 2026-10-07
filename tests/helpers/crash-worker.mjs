// Deliberate process termination at the gate boundary; never exposed as HTTP inputs.
import { openAuthority } from './fixture.mjs';
const [dir, token, objectId, epochString, stage] = process.argv.slice(2);
const hooks = {};
hooks[stage] = () => process.exit(stage === 'beforeCommit' ? 71 : 72);
const authority = await openAuthority(dir, hooks);
const session = authority.authenticate(token);
await authority.claim(session, objectId, Number(epochString));
authority.close();
process.exit(3); // Hook was not reached, therefore this run cannot establish the crash result.
