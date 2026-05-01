import { webcrypto, randomUUID } from 'crypto';
import type { LPOffer, ProtocolOffer, SettlementResult } from './engine/matchingEngine';

export { randomUUID };

export const lpStore: LPOffer[] = [];
export const protocolStore: ProtocolOffer[] = [];
export const settlementStore = new Map<string, SettlementResult>();

let _mxePrivateKey: CryptoKey;
let _mxePublicKeyB64: string;

export function getMxePrivateKey(): CryptoKey {
  if (!_mxePrivateKey) throw new Error('MXE key pair not initialized');
  return _mxePrivateKey;
}

export function getMxePublicKeyB64(): string {
  if (!_mxePublicKeyB64) throw new Error('MXE key pair not initialized');
  return _mxePublicKeyB64;
}

export async function initMxeKeyPair(): Promise<void> {
  const keyPair = (await webcrypto.subtle.generateKey(
    { name: 'X25519' } as AlgorithmIdentifier,
    true,
    ['deriveBits']
  )) as CryptoKeyPair;

  _mxePrivateKey = keyPair.privateKey;

  const rawPub = await webcrypto.subtle.exportKey('raw', keyPair.publicKey);
  _mxePublicKeyB64 = Buffer.from(rawPub).toString('base64');
}
