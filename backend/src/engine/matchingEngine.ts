import { webcrypto } from 'crypto';

const { subtle } = webcrypto;

export interface LPOffer {
  id: string;
  encryptedCapital: string;
  encryptedMinYield: string;
  iv: string;
  clientPublicKey: string;
}

export interface ProtocolOffer {
  id: string;
  encryptedDemand: string;
  encryptedMaxRate: string;
  iv: string;
  clientPublicKey: string;
}

export interface MatchResult {
  lpId: string;
  protocolId: string;
  clearingRate: number;
  capitalAllocated: number;
}

export interface SettlementResult {
  matches: MatchResult[];
  totalCapitalMatched: number;
  averageClearingRate: number;
  participantCount: number;
  settledAt: string;
  algorithmHash: string;
}

// Derives a distinct AES-GCM-256 key per field via X25519 ECDH → HKDF-SHA256.
// Using different `fieldInfo` strings per field is safe even with a shared IV.
async function deriveAesKey(
  mxePrivateKey: CryptoKey,
  clientPublicKeyB64: string,
  fieldInfo: string
): Promise<CryptoKey> {
  const clientPubBytes = Buffer.from(clientPublicKeyB64, 'base64');

  const clientPublicKey = await subtle.importKey(
    'raw',
    clientPubBytes,
    { name: 'X25519' } as AlgorithmIdentifier,
    false,
    []
  );

  // X25519 always produces 32 bytes; the length param is advisory only
  const sharedBits = await subtle.deriveBits(
    { name: 'X25519', public: clientPublicKey } as AlgorithmIdentifier,
    mxePrivateKey,
    256
  );

  const hkdfKey = await subtle.importKey('raw', sharedBits, { name: 'HKDF' }, false, [
    'deriveKey',
  ]);

  return subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(32),
      info: new TextEncoder().encode(`yield-optimizer-v1:${fieldInfo}`),
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
}

async function decryptField(
  ciphertextB64: string,
  ivB64: string,
  mxePrivateKey: CryptoKey,
  clientPublicKeyB64: string,
  fieldInfo: string
): Promise<number> {
  const aesKey = await deriveAesKey(mxePrivateKey, clientPublicKeyB64, fieldInfo);
  const ciphertext = Buffer.from(ciphertextB64, 'base64');
  const iv = Buffer.from(ivB64, 'base64');
  const plaintext = await subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ciphertext);
  return parseFloat(new TextDecoder().decode(plaintext));
}

function round8(n: number): number {
  return Math.round(n * 1e8) / 1e8;
}

export async function matchOffers(
  lps: LPOffer[],
  protocols: ProtocolOffer[],
  mxePrivateKey: CryptoKey
): Promise<SettlementResult> {
  const [decryptedLPs, decryptedProtocols] = await Promise.all([
    Promise.all(
      lps.map(async (lp) => ({
        id: lp.id,
        capital: await decryptField(
          lp.encryptedCapital,
          lp.iv,
          mxePrivateKey,
          lp.clientPublicKey,
          'capital'
        ),
        minYield: await decryptField(
          lp.encryptedMinYield,
          lp.iv,
          mxePrivateKey,
          lp.clientPublicKey,
          'minYield'
        ),
      }))
    ),
    Promise.all(
      protocols.map(async (p) => ({
        id: p.id,
        demand: await decryptField(
          p.encryptedDemand,
          p.iv,
          mxePrivateKey,
          p.clientPublicKey,
          'demand'
        ),
        maxRate: await decryptField(
          p.encryptedMaxRate,
          p.iv,
          mxePrivateKey,
          p.clientPublicKey,
          'maxRate'
        ),
      }))
    ),
  ]);

  // Sealed double auction:
  // LPs sorted by yield floor ascending  → cheapest capital offered first
  // Protocols sorted by max rate descending → most-willing borrowers matched first
  const sortedLPs = [...decryptedLPs].sort((a, b) => a.minYield - b.minYield);
  const sortedProtocols = [...decryptedProtocols].sort((a, b) => b.maxRate - a.maxRate);

  const matches: MatchResult[] = [];
  const remainingDemand = new Map(sortedProtocols.map((p) => [p.id, p.demand]));

  for (const lp of sortedLPs) {
    let remainingCapital = lp.capital;

    for (const protocol of sortedProtocols) {
      if (remainingCapital <= 0) break;
      if (lp.minYield > protocol.maxRate) continue;

      const available = remainingDemand.get(protocol.id) ?? 0;
      if (available <= 0) continue;

      const allocated = Math.min(remainingCapital, available);
      const clearingRate = (lp.minYield + protocol.maxRate) / 2;

      matches.push({
        lpId: lp.id,
        protocolId: protocol.id,
        clearingRate: round8(clearingRate),
        capitalAllocated: round8(allocated),
      });

      remainingDemand.set(protocol.id, available - allocated);
      remainingCapital -= allocated;
    }
  }

  const totalCapitalMatched = matches.reduce((sum, m) => sum + m.capitalAllocated, 0);
  const averageClearingRate =
    totalCapitalMatched > 0
      ? matches.reduce((sum, m) => sum + m.clearingRate * m.capitalAllocated, 0) /
        totalCapitalMatched
      : 0;

  const participantCount = new Set([
    ...matches.map((m) => m.lpId),
    ...matches.map((m) => m.protocolId),
  ]).size;

  const settledAt = new Date().toISOString();

  const hashPayload = JSON.stringify({
    algorithm: 'sealed-double-auction-v1',
    lpCount: lps.length,
    protocolCount: protocols.length,
    matchCount: matches.length,
    settledAt,
  });
  const hashBuffer = await subtle.digest(
    'SHA-256',
    new TextEncoder().encode(hashPayload)
  );
  const algorithmHash = Buffer.from(hashBuffer).toString('hex');

  return {
    matches,
    totalCapitalMatched: round8(totalCapitalMatched),
    averageClearingRate: round8(averageClearingRate),
    participantCount,
    settledAt,
    algorithmHash,
  };
}
