import { bytesToHex, hexToNumber, numberToBytesBE } from "@li0ard/gost3413/dist/utils";

export const bytesToNumberLE = (bytes: Uint8Array): bigint => hexToNumber(bytesToHex(bytes.slice().reverse()));
export const numberToBytesLE = (n: bigint, len: number): Uint8Array => numberToBytesBE(n, len).reverse();

export const bytesToUint64s = (b: Uint8Array): BigUint64Array => {
    const size = Math.floor(b.length / 8);
    const result = new BigUint64Array(size);
    
    for (let i = 0; i < size; i++) result[i] = bytesToNumberLE(b.slice(i * 8, i * 8 + 8));
    return result;
}

export const uint64sToBytes = (w: BigUint64Array): Uint8Array => {
    const result = new Uint8Array(w.length * 8);
    for (let i = 0; i < w.length; i++) result.set(numberToBytesLE(w[i], 8), i * 8);
    return result;
}

export const swap_block = (k: BigUint64Array, N: number) => {
    if (N <= 1) return;
    const t = k[0];
    for (let i = 0; i < N - 1; i++) k[i] = k[i + 1];
    k[N - 1] = t;
}

export const equalBytes = (a: Uint8Array, b: Uint8Array): boolean => {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
}