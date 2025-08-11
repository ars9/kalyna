import { Kalyna } from "../const";
import { bytesToUint64s, uint64sToBytes } from "../utils";
import { IMC, add_constant, addkey, subkey, swap_block, G, G0, GL, IG, IGL } from "./transforms"

const N = 8

const make_odd_key = (evenkey: BigUint64Array, oddkey: BigUint64Array) => {
    let evenkeys = uint64sToBytes(evenkey);
    let oddkeys = uint64sToBytes(oddkey);

    oddkeys.set(evenkeys.slice(19, 64));
    oddkeys.set(evenkeys.slice(0, 19), 64-19);

    let res = bytesToUint64s(oddkeys);
    oddkey.set(res);
}

/** Kalyna 512 bit version */
export class Kalyna512 implements Kalyna {
    public readonly blockSize = 64;
    erk: BigUint64Array;
    drk: BigUint64Array;

    /**
     * Kalyna 512 bit version
     * @param key Encryption key
     */
    constructor(key: Uint8Array) {
        if(key.length != this.blockSize) throw new Error("Invalid key length");

        this.erk = new BigUint64Array(152);
        this.drk = new BigUint64Array(152);

        this.expandKey(key);
    }

    public encrypt(in_: Uint8Array): Uint8Array {
        let t1 = new BigUint64Array(N),
            t2 = new BigUint64Array(N);

        let ins = bytesToUint64s(in_);

        let rk = this.erk.slice();

        addkey(ins, t1, rk, N);

        for (let i = 0; i < 17; i++) {
            const roundKey = rk.subarray(N + i * N);
            if (i % 2 === 0) G(t1, t2, roundKey, N);
            else G(t2, t1, roundKey, N);
        }
        GL(t2, t1, rk.subarray(144), N);
        return uint64sToBytes(t1);
    }

    public decrypt(in_: Uint8Array): Uint8Array {
        let t1 = new BigUint64Array(N),
            t2 = new BigUint64Array(N);

        let ins = bytesToUint64s(in_);

        let rk = this.drk.slice();

        subkey(ins, t1, rk.subarray(144), N);

        IMC(t1, N);
        for (let i = 0; i < 17; i++) {
            const roundKey = rk.subarray(136 - i * N);
            if (i % 2 === 0) IG(t1, t2, roundKey, N);
            else IG(t2, t1, roundKey, N);
        }
        IGL(t2, t1, rk, N);

        return uint64sToBytes(t1);
    }

    private expandKey(key: Uint8Array) {
        let ks = new BigUint64Array(8),
            ksc = new BigUint64Array(8),
            t1 = new BigUint64Array(8),
            t2 = new BigUint64Array(8),
            k = new BigUint64Array(8);
    
        t1[0] = 17n;

        let keys = bytesToUint64s(key);

        addkey(t1, t2, keys, N);
        G(t2, t1, keys, N);
        GL(t1, t2, keys, N);
        G0(t2, ks, N);

        let constant = 0x0001000100010001n;
        let rk = new BigUint64Array(152);

        k = keys.slice(0, 8);

        for (let i = 0; i < 10; i++) {
            const offset = i * 16;
        
            if (i > 0) swap_block(k, N);
        
            add_constant(ks, ksc, constant, N);
            addkey(k, t2, ksc, N);
            G(t2, t1, ksc, N);
            GL(t1, rk.subarray(offset), ksc, N);
        
            if (i < 9) make_odd_key(rk.subarray(offset), rk.subarray(offset + 8));
        
            constant <<= 1n;
        }

        this.erk = rk.slice();
        for (let i = 136; i > 0; i -= 8) IMC(rk.subarray(i), N);
        this.drk = rk.slice();
    }
}