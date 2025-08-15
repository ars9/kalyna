import { bytesToUint64s, uint64sToBytes, swap_block } from "../utils";
import { KalynaBase } from "./kalyna";

const make_odd_key = (evenkey: BigUint64Array, oddkey: BigUint64Array) => {
    let evenkeys = uint64sToBytes(evenkey);
    let oddkeys = uint64sToBytes(oddkey);

    oddkeys.set(evenkeys.slice(19, 64));
    oddkeys.set(evenkeys.slice(0, 19), 64-19);

    let res = bytesToUint64s(oddkeys);
    oddkey.set(res);
}

export class Kalyna512 extends KalynaBase {
    constructor(key: Uint8Array) {
        super(8, 17, 144);
        if (key.length !== this.blockSize) throw new Error("Invalid key length");
        this.expandKey(key);
    }

    expandKey(key: Uint8Array) {
        let ks = new BigUint64Array(this.N),
            ksc = new BigUint64Array(this.N),
            t1 = new BigUint64Array(this.N),
            t2 = new BigUint64Array(this.N),
            k = new BigUint64Array(this.N);
    
        t1[0] = 17n;

        let keys = bytesToUint64s(key);

        this.addkey(t1, t2, keys);
        this.G(t2, t1, keys);
        this.GL(t1, t2, keys);
        this.G0(t2, ks);

        let constant = 0x0001000100010001n;
        let rk = new BigUint64Array(152);

        k = keys.slice(0, this.N);

        for (let i = 0; i < 10; i++) {
            const offset = i * 16;
        
            if (i > 0) swap_block(k, this.N);
        
            this.add_constant(ks, ksc, constant);
            this.addkey(k, t2, ksc);
            this.G(t2, t1, ksc);
            this.GL(t1, rk.subarray(offset), ksc);
        
            if (i < 9) make_odd_key(rk.subarray(offset), rk.subarray(offset + this.N));
        
            constant <<= 1n;
        }

        this.erk = rk.slice();
        for (let i = 136; i > 0; i -= 8) this.IMC(rk.subarray(i));
        this.drk = rk.slice();
    }
}