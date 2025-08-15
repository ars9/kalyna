import { IS, IT, KUPYNA_T, S, type Kalyna } from "../const";
import { bytesToUint64s, uint64sToBytes } from "../utils";

export abstract class KalynaBase implements Kalyna {
    public erk!: BigUint64Array;
    public drk!: BigUint64Array;
    public readonly blockSize: number;

    constructor(public readonly N: number, protected numRounds: number, protected glOffset: number) {
        this.blockSize = N << 3;
    }

    abstract expandKey(key: Uint8Array): void;

    protected addkey(x: BigUint64Array, y: BigUint64Array, k: BigUint64Array) {
        for (let i = 0; i < this.N; i++) y[i] = x[i] + k[i];
    }

    protected subkey(x: BigUint64Array, y: BigUint64Array, k: BigUint64Array) {
        for (let i = 0; i < this.N; i++) y[i] = x[i] - k[i];
    }

    protected add_constant(src: BigUint64Array, dst: BigUint64Array, constant: bigint) {
        for(let i = 0; i < this.N; i++) dst[i] = src[i] + constant;
    }

    protected byte(a: bigint): number { return Number(a & 0xFFn); }

    protected G0(x: BigUint64Array, y: BigUint64Array) {
        for (let i = 0; i < this.N; i++) {
            y[i] = 0n;
            for (let j = 0; j < 8; j++) {
                const wordOffset = this.N === 8 ? j : this.N === 4 ? Math.floor(j / 2) : Math.floor(j / 4);
                y[i] ^= KUPYNA_T[j][this.byte(x[(i - wordOffset + this.N) % this.N] >> BigInt(j << 3))];
            }
        }
    }

    protected G(x: BigUint64Array, y: BigUint64Array, k: BigUint64Array) {
        for (let i = 0; i < this.N; i++) {
            y[i] = k[i];
            for (let j = 0; j < 8; j++) {
                const wordOffset = this.N === 8 ? j : this.N === 4 ? Math.floor(j / 2) : Math.floor(j / 4);
                y[i] ^= KUPYNA_T[j][this.byte(x[(i - wordOffset + this.N) % this.N] >> BigInt(j << 3))];
            }
        }
    }

    protected GL(x: BigUint64Array, y: BigUint64Array, k: BigUint64Array) {
        for (let i = 0; i < this.N; i++) {
            let temp = 0n;
            for (let j = 0; j < 8; j++) {
                const wordOffset = this.N === 8 ? j : this.N === 4 ? Math.floor(j / 2) : Math.floor(j / 4);
                temp ^= KUPYNA_T[j][this.byte(x[(i - wordOffset + this.N) % this.N] >> BigInt(j << 3))];
            }
            y[i] = k[i] + temp;
        }
    }

    protected IMC(x: BigUint64Array) {
        for (let i = 0; i < this.N; i++) {
            const v = x[i];
            x[i] = IT[0][S[0][this.byte(v)]] ^
                IT[1][S[1][this.byte(v >> 8n)]] ^
                IT[2][S[2][this.byte(v >> 16n)]] ^
                IT[3][S[3][this.byte(v >> 24n)]] ^
                IT[4][S[0][this.byte(v >> 32n)]] ^
                IT[5][S[1][this.byte(v >> 40n)]] ^
                IT[6][S[2][this.byte(v >> 48n)]] ^
                IT[7][S[3][this.byte(v >> 56n)]];
        }
    }

    protected IG(x: BigUint64Array, y: BigUint64Array, k: BigUint64Array) {
        for (let i = 0; i < this.N; i++) {
            let result = k[i];
            for (let j = 0; j < 8; j++) {
                const wordOffset = this.N === 8 ? j : this.N === 4 ? Math.floor(j / 2) : Math.floor(j / 4);
                result ^= IT[j][this.byte(x[(i + wordOffset) % this.N] >> BigInt(j << 3))];
            }
            y[i] = result;
        }
    }

    protected IGL(x: BigUint64Array, y: BigUint64Array, k: BigUint64Array) {
        for (let i = 0; i < this.N; i++) {
            let result = 0n;
            for (let j = 0; j < 8; j++) {
                const wordOffset = this.N === 8 ? j : this.N === 4 ? Math.floor(j / 2) : Math.floor(j / 4);
                const shift = BigInt(j << 3);
                result ^= BigInt(IS[j % 4][this.byte(x[(i + wordOffset) % this.N] >> shift)]) << shift;
            }
            y[i] = result - k[i];
        }
    }

    public encrypt(in_: Uint8Array): Uint8Array {
        if(in_.length != this.blockSize) throw new Error(`Input buffer to short (need - ${this.blockSize}, got - ${in_.length})`);
        const t1 = new BigUint64Array(this.N);
        const t2 = new BigUint64Array(this.N);
        const ins = bytesToUint64s(in_);
        const rk = this.erk.slice();

        this.addkey(ins, t1, rk);

        for (let i = 0; i < this.numRounds; i++) {
            const roundKey = rk.subarray(this.N + i * this.N);
            if (i % 2 === 0) this.G(t1, t2, roundKey);
            else this.G(t2, t1, roundKey);
        }

        this.GL(t2, t1, rk.subarray(this.glOffset));
        return uint64sToBytes(t1);
    }

    public decrypt(in_: Uint8Array): Uint8Array {
        if(in_.length != this.blockSize) throw new Error(`Input buffer to short (need - ${this.blockSize}, got - ${in_.length})`);
        const t1 = new BigUint64Array(this.N);
        const t2 = new BigUint64Array(this.N);
        const ins = bytesToUint64s(in_);
        const rk = this.drk.slice();

        this.subkey(ins, t1, rk.subarray(this.glOffset));
        this.IMC(t1);

        for (let i = 0; i < this.numRounds; i++) {
            const roundKey = rk.subarray(this.glOffset - this.N - i * this.N);
            if (i % 2 === 0) this.IG(t1, t2, roundKey);
            else this.IG(t2, t1, roundKey);
        }

        this.IGL(t2, t1, rk);
        return uint64sToBytes(t1);
    }
}