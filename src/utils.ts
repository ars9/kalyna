import { bytesToHex, hexToNumber, numberToBytesBE } from "@li0ard/gost3413/dist/utils";

export function bytesToNumberLE(bytes: Uint8Array): bigint {
    return hexToNumber(bytesToHex(bytes.slice().reverse()));
}

export function numberToBytesLE(n: number | bigint, len: number): Uint8Array {
    return numberToBytesBE(n, len).reverse();
}

export const byte = (a: bigint): number => Number(a & 0xFFn);

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