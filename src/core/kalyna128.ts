import { Kalyna } from "../const";
import { bytesToUint64s, uint64sToBytes } from "../utils";
import { add_constant, addkey, G, G0, GL, IMC, subkey, swap_block, IG, IGL } from "./transforms";

const N = 2;

const make_odd_key128 = (evenkey: BigUint64Array, oddkey: BigUint64Array) => {
    let evenkeys = uint64sToBytes(evenkey);
    let oddkeys = uint64sToBytes(oddkey);

    oddkeys.set(evenkeys.slice(7, 16));
    oddkeys.set(evenkeys.slice(0, 7), 9);

    let res = bytesToUint64s(oddkeys);
    oddkey.set(res);
}

/** Kalyna 128 bit version */
export class Kalyna128 implements Kalyna {
    public readonly blockSize = 16;
    erk: BigUint64Array;
    drk: BigUint64Array;

    /**
     * Kalyna 128 bit version
     * @param key Encryption key
     */
    constructor(key: Uint8Array) {
        if(key.length != this.blockSize) throw new Error("Invalid key length");

        this.erk = new BigUint64Array(24);
        this.drk = new BigUint64Array(24);

        this.expandKey(key);
    }

    public encrypt(in_: Uint8Array): Uint8Array {
        let t1 = new BigUint64Array(N),
            t2 = new BigUint64Array(N);
        
        let ins = bytesToUint64s(in_);

        let rk = this.erk.slice();

        addkey(ins, t1, rk, N);

        for(let i = 2; i < 18; i += 4) {
            G(t1, t2, rk.subarray(i), N); // i + 1
            G(t2, t1, rk.subarray(i+2), N); // i + 2
        }

        G(t1, t2, rk.subarray(18), N); // 9
        GL(t2, t1, rk.subarray(20), N); // 10
        
        return uint64sToBytes(t1);
    }

    public decrypt(in_: Uint8Array): Uint8Array {
        let t1 = new BigUint64Array(N),
            t2 = new BigUint64Array(N);
        
        let ins = bytesToUint64s(in_);

        let rk = this.drk.slice();

        subkey(ins, t1, rk.subarray(20), N);

        IMC(t1, N);
        for(let i = 18; i > 2; i -= 4) {
            IG(t1, t2, rk.subarray(i), N);
            IG(t2, t1, rk.subarray(i - 2), N);
        }

        IG(t1, t2, rk.subarray(2), N);
        IGL(t2, t1, rk, N);

        return uint64sToBytes(t1);
    }

    private expandKey(key: Uint8Array) {
        let ks = new BigUint64Array(2),
            ksc = new BigUint64Array(2),
            t1 = new BigUint64Array(2),
            t2 = new BigUint64Array(2),
            k = new BigUint64Array(2),
            kswapped = new BigUint64Array(2);
        
        let keys = bytesToUint64s(key);

        t1[0] = 5n;

        addkey(t1, t2, keys, N);
        G(t2, t1, keys, N);
        GL(t1, t2, keys, N);
        G0(t2, ks, N);

        let constant = 0x0001000100010001n;
        let rk = new BigUint64Array(24);

        k = keys.slice(0, 2);
        kswapped[1] = k[0];
        kswapped[0] = k[1];

        for (let i = 0; i < 6; i++) {
            const offset = i * 4;
            
            add_constant(ks, ksc, constant, N);
            addkey(i % 2 === 0 ? k : kswapped, t2, ksc, N);
            G(t2, t1, ksc, N);
            GL(t1, rk.subarray(offset), ksc, N);
            
            if (i < 5) make_odd_key128(rk.subarray(offset), rk.subarray(offset + 2));
            constant <<= 1n;
        }

        this.erk = rk.slice();
        for (let i = 18; i > 0; i -= 2) IMC(rk.subarray(i), N);
        this.drk = rk.slice();
    }
}

/** Kalyna 128 bit (and 256 bit key) version */
export class Kalyna128_256 implements Kalyna {
    public readonly blockSize = 16;
    erk: BigUint64Array;
    drk: BigUint64Array;

    /**
     * Kalyna 128 bit (and 256 bit key) version
     * @param key Encryption key
     */
    constructor(key: Uint8Array) {
        if(key.length != this.blockSize * 2) throw new Error("Invalid key length");

        this.erk = new BigUint64Array(32);
        this.drk = new BigUint64Array(32);

        this.expandKey(key);
    }

    public encrypt(in_: Uint8Array): Uint8Array {
        let t1 = new BigUint64Array(2),
            t2 = new BigUint64Array(2);
        
        let ins = bytesToUint64s(in_);

        let rk = this.erk.slice();

        addkey(ins, t1, rk, N);
        for (let i = 0; i < 13; i++) {
            const roundKey = rk.subarray(2 + i * 2);
    
            if (i % 2 === 0) G(t1, t2, roundKey, N);
            else G(t2, t1, roundKey, N);
        }
        GL(t2, t1, rk.subarray(28), N); // 14

        return uint64sToBytes(t1);
    }

    public decrypt(in_: Uint8Array): Uint8Array {
        let t1 = new BigUint64Array(2),
            t2 = new BigUint64Array(2);
        
        let ins = bytesToUint64s(in_);

        let rk = this.drk.slice();

        subkey(ins, t1, rk.subarray(28), N);

        IMC(t1, N);
        for (let i = 0; i < 13; i++) {
            const roundKey = rk.subarray(26 - i * 2);
            if (i % 2 === 0) IG(t1, t2, roundKey, N);
            else IG(t2, t1, roundKey, N);
        }
        IGL(t2, t1, rk.subarray(0), N);

        return uint64sToBytes(t1);
    }

    private expandKey(key: Uint8Array) {
        let ks = new BigUint64Array(2),
            ksc = new BigUint64Array(2),
            t1 = new BigUint64Array(2),
            t2 = new BigUint64Array(2),
            ka = new BigUint64Array(2),
            ko = new BigUint64Array(2),
            k = new BigUint64Array(4);
    
        let keys = bytesToUint64s(key);

        t1[0] = 7n;
        ka = keys.slice(0, 2);
        ko = keys.slice(2);

        addkey(t1, t2, ka, N);
        G(t2, t1, ko, N);
        GL(t1, t2, ka, N);
        G0(t2, ks, N);

        let constant = 0x0001000100010001n;
        let rk = new BigUint64Array(32);

        k = keys.slice(0, 4);

        for (let i = 0; i < 8; i++) {
            const offset = i * 4;
            if (i > 0 && i % 2 === 0) swap_block(k, N*2);
        
            add_constant(ks, ksc, constant, N);
            addkey(i % 2 === 0 ? k : k.subarray(2), t2, ksc, N);
            G(t2, t1, ksc, N);
            GL(t1, rk.subarray(offset), ksc, N);
        
            if (i < 7) make_odd_key128(rk.subarray(offset), rk.subarray(offset + 2));
            constant <<= 1n;
        }

        this.erk = rk.slice();
        for (let i = 26; i > 0; i -= 2) IMC(rk.subarray(i), N);
        this.drk = rk.slice();
    }
}