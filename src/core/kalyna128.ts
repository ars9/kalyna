import { bytesToUint64s, uint64sToBytes, swap_block } from "../utils";
import { KalynaBase } from "./kalyna";

const make_odd_key128 = (evenkey: BigUint64Array, oddkey: BigUint64Array) => {
    let evenkeys = uint64sToBytes(evenkey);
    let oddkeys = uint64sToBytes(oddkey);

    oddkeys.set(evenkeys.slice(7, 16));
    oddkeys.set(evenkeys.slice(0, 7), 9);

    let res = bytesToUint64s(oddkeys);
    oddkey.set(res);
}

export class Kalyna128 extends KalynaBase {
    constructor(key: Uint8Array) {
        super(2, 10, 20);
        if (key.length !== this.blockSize) throw new Error("Invalid key length");
        this.expandKey(key);
    }

    expandKey(key: Uint8Array) {
        let ks = new BigUint64Array(2),
            ksc = new BigUint64Array(2),
            t1 = new BigUint64Array(2),
            t2 = new BigUint64Array(2),
            k = new BigUint64Array(2),
            kswapped = new BigUint64Array(2);
        
        let keys = bytesToUint64s(key);

        t1[0] = 5n;

        this.addkey(t1, t2, keys);
        this.G(t2, t1, keys);
        this.GL(t1, t2, keys);
        this.G0(t2, ks);

        let constant = 0x0001000100010001n;
        let rk = new BigUint64Array(24);

        k = keys.slice(0, this.N);
        kswapped[1] = k[0];
        kswapped[0] = k[1];

        for (let i = 0; i < 6; i++) {
            const offset = i * 4;
            
            this.add_constant(ks, ksc, constant);
            this.addkey(i % 2 === 0 ? k : kswapped, t2, ksc);
            this.G(t2, t1, ksc);
            this.GL(t1, rk.subarray(offset), ksc);
            
            if (i < 5) make_odd_key128(rk.subarray(offset), rk.subarray(offset + this.N));
            constant <<= 1n;
        }

        this.erk = rk.slice();
        for (let i = 18; i > 0; i -= 2) this.IMC(rk.subarray(i));
        this.drk = rk.slice();
    }
}

export class Kalyna128_256 extends KalynaBase {
    constructor(key: Uint8Array) {
        super(2, 13, 28);
        if (key.length !== this.blockSize * 2) throw new Error("Invalid key length");
        this.expandKey(key);
    }

    expandKey(key: Uint8Array) {
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

        this.addkey(t1, t2, ka);
        this.G(t2, t1, ko);
        this.GL(t1, t2, ka);
        this.G0(t2, ks);

        let constant = 0x0001000100010001n;
        let rk = new BigUint64Array(32);

        k = keys.slice(0, 4);

        for (let i = 0; i < 8; i++) {
            const offset = i * 4;
            if (i > 0 && i % 2 === 0) swap_block(k, this.N*2);
        
            this.add_constant(ks, ksc, constant);
            this.addkey(i % 2 === 0 ? k : k.subarray(2), t2, ksc);
            this.G(t2, t1, ksc);
            this.GL(t1, rk.subarray(offset), ksc);
        
            if (i < 7) make_odd_key128(rk.subarray(offset), rk.subarray(offset + 2));
            constant <<= 1n;
        }

        this.erk = rk.slice();
        for (let i = 26; i > 0; i -= 2) this.IMC(rk.subarray(i));
        this.drk = rk.slice();
    }
}