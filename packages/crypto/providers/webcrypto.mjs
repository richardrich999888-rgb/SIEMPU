// The default WebCrypto provider lives in crypto.mjs so that the browser module graph
// stays cacheable by previously deployed service workers. This path is kept stable.
export { DEMO_SUITE, negotiateSuite, createWebCryptoProvider } from '../crypto.mjs';
