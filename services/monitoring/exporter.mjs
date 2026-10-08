import { redactSecurityEvents } from './collector.mjs';
import { packet, canonical, hash, verifyPacket } from '../control/primitives.mjs';
import { requestBytes } from '../../packages/transport/tls.mjs';
export function createTelemetryExporter({ url, tls, collectorKey }) {
  if (!tls || new URL(url).protocol !== 'https:') throw new Error('MONITORING_TLS_REQUIRED');
  return {
    state: 'NOT_DELIVERED',
    lastDeliveredAt: null,
    async deliver(authority) {
      try {
        const batch = packet(authority.key, redactSecurityEvents(authority));
        const result = await requestBytes(url, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: canonical(batch),
          tls,
          timeoutMs: 2000,
          maxBytes: 32768,
        });
        const receipt = JSON.parse(result.body);
        if (
          result.status !== 200 ||
          !verifyPacket(collectorKey, receipt) ||
          receipt.payload.batchDigest !== hash(canonical(batch))
        )
          throw new Error('COLLECTOR_ACK_INVALID');
        this.state = 'DELIVERED';
        this.lastDeliveredAt = Date.now();
        return receipt;
      } catch {
        this.state = 'DEGRADED';
        return null;
      }
    },
  };
}
