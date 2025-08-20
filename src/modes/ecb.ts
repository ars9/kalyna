import { ecb_encrypt, ecb_decrypt } from "@li0ard/gost3413";
import type { KalynaBase } from "../core";

/**
 * Encrypts data using Electronic Codebook (ECB) mode
 * @param cipherClass Initialized cipher class
 * @param data Data to be encrypted
 */
export const encryptECB = (cipherClass: KalynaBase, data: Uint8Array): Uint8Array => {
    const encrypter = (buf: Uint8Array) => (cipherClass.encrypt(buf));
    return ecb_encrypt(encrypter, cipherClass.blockSize, data);
}

/**
 * Decrypts data using Electronic Codebook (ECB) mode
 * @param cipherClass Initialized cipher class
 * @param data Data to be encrypted
 */
export const decryptECB = (cipherClass: KalynaBase, data: Uint8Array): Uint8Array => {
    const decrypter = (buf: Uint8Array) => (cipherClass.decrypt(buf));
    return ecb_decrypt(decrypter, cipherClass.blockSize, data);
}