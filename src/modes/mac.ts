import { xor } from "@ars9/gost3413/dist/utils";
import type { KalynaBase } from "../core";
import { pad } from "../padding";

/**
 * Compute CMAC
 * @param cipherClass Initialized cipher class
 * @param in_ Data to be authenticated
 */
export const cmac = (cipherClass: KalynaBase, data: Uint8Array, q: number = 16): Uint8Array => {
    let zeroBlock = new Uint8Array(cipherClass.blockSize);

    if(data.length % cipherClass.blockSize !== 0) {
        data = pad(data, cipherClass.blockSize);
        zeroBlock[0] = 1;
    }

    let Kd = cipherClass.encrypt(zeroBlock);

    let c: Uint8Array = new Uint8Array(cipherClass.blockSize);
    const numBlocks = data.length / cipherClass.blockSize;

    for (let i = 0; i < numBlocks - 1; i++) {
        const blockStart = i * cipherClass.blockSize;
        const block = data.slice(blockStart, blockStart + cipherClass.blockSize);
        
        c = xor(c, block);
        c = cipherClass.encrypt(c);
    }

    const lastBlockStart = (numBlocks - 1) * cipherClass.blockSize;
    const lastBlock = data.slice(lastBlockStart, lastBlockStart + cipherClass.blockSize);
    
    c = cipherClass.encrypt(xor(xor(c, lastBlock), Kd));

    return c.slice(0, q);
}