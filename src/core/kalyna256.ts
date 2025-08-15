import { bytesToUint64s, uint64sToBytes, swap_block } from "../utils";
import { KalynaBase } from "./kalyna";

const make_odd_key256 = (evenkey: BigUint64Array, oddkey: BigUint64Array) => {
    let evenkeys = uint64sToBytes(evenkey);
    let oddkeys = uint64sToBytes(oddkey);

    oddkeys.set(evenkeys.slice(11, 32));
    oddkeys.set(evenkeys.slice(0, 11), 21);

    let res = bytesToUint64s(oddkeys);
    oddkey.set(res);
}

export class Kalyna256 extends KalynaBase {
    constructor(key: Uint8Array) {
        super(4, 13, 56);
        if (key.length !== this.blockSize) throw new Error("Invalid key length");
        this.expandKey(key);
    }

    expandKey(key: Uint8Array) {
        let ks = new BigUint64Array(4),
            ksc = new BigUint64Array(4),
            t1 = new BigUint64Array(4),
            t2 = new BigUint64Array(4),
            k = new BigUint64Array(8);
    
        let keys = bytesToUint64s(key);

        t1[0] = 9n;

        this.addkey(t1, t2, keys);
        this.G(t2, t1, keys);
        this.GL(t1, t2, keys);
        this.G0(t2, ks);

        let constant = 0x0001000100010001n;
        let rk = new BigUint64Array(64);

        k.set(keys.slice(0, this.N));

        for (let i = 0; i < 8; i++) {
            const offset = i << 3;
        
            if (i > 0) swap_block(k, this.N);
        
            this.add_constant(ks, ksc, constant);
            this.addkey(k, t2, ksc);
            this.G(t2, t1, ksc);
            this.GL(t1, rk.subarray(offset), ksc);
        
            if (i < 7) make_odd_key256(rk.subarray(offset), rk.subarray(offset + this.N));
            constant <<= 1n;
        }

        this.erk = rk.slice();
        for (let i = 52; i > 0; i -= 4) this.IMC(rk.subarray(i));
        this.drk = rk.slice();
    }
}

export class Kalyna256_512 extends KalynaBase {
    constructor(key: Uint8Array) {
        super(4, 17, 72);
        if (key.length !== this.blockSize * 2) throw new Error("Invalid key length");
        this.expandKey(key)
    }

    expandKey(key: Uint8Array) {
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

        this.addkey(t1, t2, ka);
        this.G(t2, t1, ko);
        this.GL(t1, t2, ka);
        this.G0(t2, ks);

        let constant = 0x0001000100010001n;
        let rk = new BigUint64Array(80);

        k = keys.slice();

        for (let i = 0; i < 10; i++) {
            const offset = i << 3;

            if (i > 0 && i % 2 === 0) swap_block(k, this.N*2);
        
            this.add_constant(ks, ksc, constant);
            this.addkey(i % 2 === 0 ? k : k.subarray(4), t2, ksc);
            this.G(t2, t1, ksc);
            this.GL(t1, rk.subarray(offset), ksc);
        
            if (i < 9) make_odd_key256(rk.subarray(offset), rk.subarray(offset + 4));
        
            constant <<= 1n;
        }

        this.erk = rk.slice();
        for (let i = 68; i > 0; i -= 4) this.IMC(rk.subarray(i));
        this.drk = rk.slice();
    }
}