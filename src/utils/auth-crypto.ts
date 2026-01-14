import { createHmac, randomBytes } from 'crypto';
import Milenage from 'milenage';
import logger from './logger';

export function generateRand(): string {
  return randomBytes(16).toString('hex').toUpperCase();
}

export interface MilenageOutput {
  mac_a: Buffer;
  mac_s: Buffer;
  res: Buffer;
  ck: Buffer;
  ik: Buffer;
  ak: Buffer;
}

export function milenage(k: Buffer, op: Buffer, rand: Buffer, sqn: Buffer, amf: Buffer): MilenageOutput {
  if (k.length !== 16) {
    throw new Error(`Invalid K length: ${k.length} (expected 16)`);
  }
  if (op.length !== 16) {
    throw new Error(`Invalid OP length: ${op.length} (expected 16)`);
  }
  if (rand.length !== 16) {
    throw new Error(`Invalid RAND length: ${rand.length} (expected 16)`);
  }
  if (sqn.length !== 6) {
    throw new Error(`Invalid SQN length: ${sqn.length} (expected 6)`);
  }
  if (amf.length !== 2) {
    throw new Error(`Invalid AMF length: ${amf.length} (expected 2)`);
  }

  const mil = new Milenage({ op_c: new Uint8Array(op), key: new Uint8Array(k) });

  const f1Result = mil.f1(new Uint8Array(rand), new Uint8Array(sqn), new Uint8Array(amf));
  const f2345Result = mil.f2345(new Uint8Array(rand));

  return {
    mac_a: Buffer.from(f1Result.mac_a),
    mac_s: f1Result.mac_s ? Buffer.from(f1Result.mac_s) : Buffer.alloc(8),
    res: Buffer.from(f2345Result.res),
    ck: Buffer.from(f2345Result.ck),
    ik: Buffer.from(f2345Result.ik),
    ak: Buffer.from(f2345Result.ak)
  };
}

export function computeKausf(ck: Buffer, ik: Buffer, servingNetworkName: string, sqnXorAk: Buffer): string {
  const key = Buffer.concat([ck, ik]);

  const snName = Buffer.from(servingNetworkName, 'utf8');
  const snNameLength = Buffer.alloc(2);
  snNameLength.writeUInt16BE(snName.length);

  const s = Buffer.concat([
    Buffer.from([0x6A]),
    snName,
    snNameLength,
    sqnXorAk,
    Buffer.from([0x00, 0x06])
  ]);

  return kdf(key, s).toString('hex').toUpperCase();
}

export function computeXresStar(res: Buffer, rand: Buffer, servingNetworkName: string, ck: Buffer, ik: Buffer): string {
  const snName = Buffer.from(servingNetworkName, 'utf8');
  const snNameLength = Buffer.alloc(2);
  snNameLength.writeUInt16BE(snName.length);

  const s = Buffer.concat([
    Buffer.from([0x6B]),
    snName,
    snNameLength,
    rand,
    Buffer.from([0x00, 0x10]),
    res,
    Buffer.from([0x00, res.length])
  ]);

  const key = Buffer.concat([ck, ik]);
  const kdfOut = kdf(key, s);
  return kdfOut.slice(kdfOut.length - 16).toString('hex').toUpperCase();
}

export function kdf(key: Buffer, s: Buffer): Buffer {
  const hmac = createHmac('sha256', key);
  hmac.update(s);
  return hmac.digest();
}

export function computeCkPrimeIkPrime(ck: Buffer, ik: Buffer, servingNetworkName: string, sqnXorAk: Buffer): { ckPrime: string, ikPrime: string } {
  const fc = 0x20;
  const snName = Buffer.from(servingNetworkName, 'utf8');
  const snNameLength = Buffer.alloc(2);
  snNameLength.writeUInt16BE(snName.length);

  const s = Buffer.concat([
    Buffer.from([fc]),
    snName,
    snNameLength,
    sqnXorAk,
    Buffer.from([0x00, 0x06])
  ]);

  const key = Buffer.concat([ck, ik]);
  const output = kdf(key, s);

  const ckPrime = output.slice(0, 16).toString('hex').toUpperCase();
  const ikPrime = output.slice(16, 32).toString('hex').toUpperCase();

  return { ckPrime, ikPrime };
}

export function computeKasme(ck: Buffer, ik: Buffer, plmnId: Buffer, sqnXorAk: Buffer): string {
  const fc = 0x10;
  const p0 = plmnId;
  const l0 = Buffer.from([0x00, 0x03]);
  const p1 = sqnXorAk;
  const l1 = Buffer.from([0x00, 0x06]);

  const s = Buffer.concat([
    Buffer.from([fc]),
    p0,
    l0,
    p1,
    l1
  ]);

  const key = Buffer.concat([ck, ik]);
  return kdf(key, s).toString('hex').toUpperCase();
}

export function processAuts(k: Buffer, op: Buffer, rand: Buffer, auts: Buffer, amf: Buffer): string | null {
  if (auts.length !== 14) {
    logger.error('Invalid AUTS length', { length: auts.length, expected: 14 });
    return null;
  }

  const sqnMsXorAkStar = auts.slice(0, 6);
  const receivedMacS = auts.slice(6, 14);

  const mil = new Milenage({ op_c: new Uint8Array(op), key: new Uint8Array(k) }) as any;
  const f5starResult = mil.f5star(new Uint8Array(rand));
  const akStar = Buffer.from(f5starResult.ak_s);

  const sqnMs = Buffer.alloc(6);
  for (let i = 0; i < 6; i++) {
    sqnMs[i] = sqnMsXorAkStar[i] ^ akStar[i];
  }

  const dummyAmf = Buffer.alloc(2);
  const f1starResult = mil.f1star(new Uint8Array(rand), new Uint8Array(sqnMs), new Uint8Array(dummyAmf));
  const expectedMacS = Buffer.from(f1starResult.mac_s);

  if (!receivedMacS.equals(expectedMacS)) {
    logger.error('MAC-S validation failed');
    return null;
  }

  const sqnMsHex = sqnMs.toString('hex').toUpperCase();
  return sqnMsHex;
}


