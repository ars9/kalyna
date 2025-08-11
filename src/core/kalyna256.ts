import { Kalyna } from "../const";
import { bytesToUint64s, uint64sToBytes } from "../utils";
import { IMC, add_constant, addkey, subkey, swap_block, G, G0, GL, IG, IGL } from "./transforms";

const N = 4;

const make_odd_key256 = (evenkey: BigUint64Array, oddkey: BigUint64Array) => {
    let evenkeys = uint64sToBytes(evenkey);
    let oddkeys = uint64sToBytes(oddkey);

    oddkeys.set(evenkeys.slice(11, 32));
    oddkeys.set(evenkeys.slice(0, 11), 21);

    let res = bytesToUint64s(oddkeys);
    oddkey.set(res);
}

/** Kalyna 256 bit version */
export class Kalyna256 implements Kalyna {
    public readonly blockSize = 32;
    erk: BigUint64Array;
    drk: BigUint64Array;

    /**
     * Kalyna 256 bit version
     * @param key Encryption key
     */
    constructor(key: Uint8Array) {
        if(key.length != this.blockSize) throw new Error("Invalid key length");

        this.erk = new BigUint64Array(64);
        this.drk = new BigUint64Array(64);

        this.expandKey(key);
    }

    public encrypt(in_: Uint8Array): Uint8Array {
        let t1 = new BigUint64Array(N),
            t2 = new BigUint64Array(N);

        let ins = bytesToUint64s(in_);

        let rk = this.erk.slice();

        addkey(ins, t1, rk, N);

        for (let i = 0; i < 13; i++) {
            const roundKey = rk.subarray(N + i * N);
    
            if (i % 2 === 0) G(t1, t2, roundKey, N);
            else G(t2, t1, roundKey, N);
        }
        GL(t2, t1, rk.subarray(56), N);

        return uint64sToBytes(t1);
    }

    public decrypt(in_: Uint8Array): Uint8Array {
        let t1 = new BigUint64Array(N),
            t2 = new BigUint64Array(N);

        let ins = bytesToUint64s(in_);

        let rk = this.drk.slice();

        subkey(ins, t1, rk.subarray(56), N);

        IMC(t1, N);
        for (let i = 0; i < 13; i++) {
            const roundKey = rk.subarray(52 - i * N);
            if (i % 2 === 0) IG(t1, t2, roundKey, N);
            else IG(t2, t1, roundKey, N);
        }
        IGL(t2, t1, rk, N);

        return uint64sToBytes(t1);
    }

    private expandKey(key: Uint8Array) {
        let ks = new BigUint64Array(4),
            ksc = new BigUint64Array(4),
            t1 = new BigUint64Array(4),
            t2 = new BigUint64Array(4),
            k = new BigUint64Array(8);
    
        let keys = bytesToUint64s(key);

        t1[0] = 9n;

        addkey(t1, t2, keys, N);
        G(t2, t1, keys, N);
        GL(t1, t2, keys, N);
        G0(t2, ks, N);

        let constant = 0x0001000100010001n;
        let rk = new BigUint64Array(64);

        k.set(keys.slice(0, 4));

        for (let i = 0; i < 8; i++) {
            const offset = i * 8;
        
            if (i > 0) swap_block(k, N);
        
            add_constant(ks, ksc, constant, N);
            addkey(k, t2, ksc, N);
            G(t2, t1, ksc, N);
            GL(t1, rk.subarray(offset), ksc, N);
        
            if (i < 7) make_odd_key256(rk.subarray(offset), rk.subarray(offset + 4));
            constant <<= 1n;
        }

        this.erk = rk.slice();
        for (let i = 52; i > 0; i -= 4) IMC(rk.subarray(i), N);
        this.drk = rk.slice();
    }
}

/** Kalyna 256 bit (and 512 bit key) version */
export class Kalyna256_512 implements Kalyna {
    public readonly blockSize = 32;
    erk: BigUint64Array;
    drk: BigUint64Array;

    /**
     * Kalyna 256 bit (and 512 bit key) version
     * @param key Encryption key
     */
    constructor(key: Uint8Array) {
        if(key.length != this.blockSize * 2) throw new Error("Invalid key length");

        this.erk = new BigUint64Array(80);
        this.drk = new BigUint64Array(80);

        this.expandKey(key);
    }

    public encrypt(in_: Uint8Array): Uint8Array {
        let t1 = new BigUint64Array(4),
            t2 = new BigUint64Array(4);
        
        let ins = bytesToUint64s(in_);

        let rk = this.erk.slice();

        addkey(ins, t1, rk, N);

        for (let i = 0; i < 17; i++) {
            const roundKey = rk.subarray(4 + i * 4);
    
            if (i % 2 === 0) G(t1, t2, roundKey, N);
            else G(t2, t1, roundKey, N);
        }
        GL(t2, t1, rk.subarray(72), N); // 18

        return uint64sToBytes(t1);
    }

    public decrypt(in_: Uint8Array): Uint8Array {
        let t1 = new BigUint64Array(4),
            t2 = new BigUint64Array(4);
        
        let ins = bytesToUint64s(in_);

        let rk = this.drk.slice();

        subkey(ins, t1, rk.subarray(72), N);

        IMC(t1, N);
        for (let i = 0; i < 17; i++) {
            const roundKey = rk.subarray(68 - i * 4);
            if (i % 2 === 0) IG(t1, t2, roundKey, N);
            else IG(t2, t1, roundKey, N);
        }
        IGL(t2, t1, rk, N);

        return uint64sToBytes(t1);
    }

    private expandKey(key: Uint8Array) {
        let ks = new BigUint64Array(4),
            ksc = new BigUint64Array(4),
            t1 = new BigUint64Array(4),
            t2 = new BigUint64Array(4),
            ka = new BigUint64Array(4),
            ko = new BigUint64Array(4),
            k = new BigUint64Array(8);
    
        let keys = bytesToUint64s(key);

        t1[0] = 13n;

        ka = keys.slice(0, 4);
        ko = keys.slice(4);

        addkey(t1, t2, ka, N);
        G(t2, t1, ko, N);
        GL(t1, t2, ka, N);
        G0(t2, ks, N);

        let constant = 0x0001000100010001n;
        let rk = new BigUint64Array(80);

        k = keys.slice();

        for (let i = 0; i < 10; i++) {
            const offset = i * 8;

            if (i > 0 && i % 2 === 0) swap_block(k, N*2);
        
            add_constant(ks, ksc, constant, N);
            addkey(i % 2 === 0 ? k : k.subarray(4), t2, ksc, N);
            G(t2, t1, ksc, N);
            GL(t1, rk.subarray(offset), ksc, N);
        
            if (i < 9) make_odd_key256(rk.subarray(offset), rk.subarray(offset + 4));
        
            constant <<= 1n;
        }

        this.erk = rk.slice();
        for (let i = 68; i > 0; i -= 4) IMC(rk.subarray(i), N);
        this.drk = rk.slice();
    }
}