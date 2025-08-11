import { concatBytes, xor } from "@li0ard/gost3413/dist/utils";
import type { Kalyna } from "../const";

/**
 * Proceed data using the Counter (CTR) mode
 * @param cipherClass Initialized cipher class
 * @param data Data to be encrypted/decrypted
 * @param iv Initialization vector
 */
export const ctr = (cipherClass: Kalyna, data: Uint8Array, iv: Uint8Array): Uint8Array => {
    if (iv.length !== cipherClass.blockSize) throw new Error("Invalid IV size");

    const keystreamBlocks: Uint8Array[] = [];
    let ctr = cipherClass.encrypt(iv);
    for (let i = 0; i < Math.ceil(data.length / cipherClass.blockSize); i++) {
        ctr[0] += 1;
        keystreamBlocks.push(cipherClass.encrypt(ctr));
    }

    return xor(concatBytes(...keystreamBlocks), data);
}