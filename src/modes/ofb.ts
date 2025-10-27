import { ofb as ofb_ } from "@ars9/gost3413";
import type { KalynaBase } from "../core";

/**
 * Proceed data using the Output Feedback (OFB) mode
 * @param cipherClass Initialized cipher class
 * @param data Data to be encrypted/decrypted
 * @param iv Initialization vector
 */
export const ofb = (cipherClass: KalynaBase, data: Uint8Array, iv: Uint8Array): Uint8Array => {
    const encrypter = (buf: Uint8Array) => (cipherClass.encrypt(buf));
    return ofb_(encrypter, cipherClass.blockSize, data, iv);
}
