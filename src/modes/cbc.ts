import { cbc_encrypt, cbc_decrypt } from "@li0ard/gost3413";
import type { KalynaBase } from "../core";

/**
 * Encrypts data using Cipher Block Chaining (CBC) mode
 * @param cipherClass Initialized cipher class
 * @param data Data to be encrypted
 * @param iv Initialization vector
 */
export const encryptCBC = (cipherClass: KalynaBase, data: Uint8Array, iv: Uint8Array): Uint8Array => {
    const encrypter = (buf: Uint8Array) => (cipherClass.encrypt(buf));
    return cbc_encrypt(encrypter, cipherClass.blockSize, data, iv);
}

/**
 * Decrypts data using Cipher Block Chaining (CBC) mode
 * @param cipherClass Initialized cipher class
 * @param data Data to be decrypted
 * @param iv Initialization vector
 */
export const decryptCBC = (cipherClass: KalynaBase, data: Uint8Array, iv: Uint8Array): Uint8Array => {
    const decrypter = (buf: Uint8Array) => (cipherClass.decrypt(buf));
    return cbc_decrypt(decrypter, cipherClass.blockSize, data, iv);
}
