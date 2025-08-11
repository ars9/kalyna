import { IS, IT, KUPYNA_T, S } from "../const";
import { byte } from "../utils";

export const addkey = (x: BigUint64Array, y: BigUint64Array, k: BigUint64Array, N: number) => {
    for (let i = 0; i < N; i++) y[i] = x[i] + k[i];
}

export const subkey = (x: BigUint64Array, y: BigUint64Array, k: BigUint64Array, N: number) => {
    for (let i = 0; i < N; i++) y[i] = x[i] - k[i];
}

export const add_constant = (src: BigUint64Array, dst: BigUint64Array, constant: bigint, N: number) => {
    for(let i = 0; i < N; i++) dst[i] = src[i] + constant;
}

export const swap_block = (k: BigUint64Array, N: number) => {
    if (N <= 1) return;
    const t = k[0];
    for (let i = 0; i < N - 1; i++) {
        k[i] = k[i + 1];
    }
    k[N - 1] = t;
}

export const G0 = (x: BigUint64Array, y: BigUint64Array, N: number) => {
    for (let i = 0; i < N; i++) {
        y[i] = 0n;
        for (let j = 0; j < 8; j++) {
            const wordOffset = N === 8 ? j : N === 4 ? Math.floor(j / 2) : Math.floor(j / 4);
            y[i] ^= KUPYNA_T[j][byte(x[(i - wordOffset + N) % N] >> BigInt(j * 8))];
        }
    }
}

export const G = (x: BigUint64Array, y: BigUint64Array, k: BigUint64Array, N: number) => {
    for (let i = 0; i < N; i++) {
        y[i] = k[i];
        for (let j = 0; j < 8; j++) {
            const wordOffset = N === 8 ? j : N === 4 ? Math.floor(j / 2) : Math.floor(j / 4);
            y[i] ^= KUPYNA_T[j][byte(x[(i - wordOffset + N) % N] >> BigInt(j * 8))];
        }
    }
}

export const GL = (x: BigUint64Array, y: BigUint64Array, k: BigUint64Array, N: number) => {
    for (let i = 0; i < N; i++) {
        let temp = 0n;
        for (let j = 0; j < 8; j++) {
            const wordOffset = N === 8 ? j : N === 4 ? Math.floor(j / 2) : Math.floor(j / 4);
            temp ^= KUPYNA_T[j][byte(x[(i - wordOffset + N) % N] >> BigInt(j * 8))];
        }
        y[i] = k[i] + temp;
    }
}

export const IMC = (x: BigUint64Array, N: number) => {
    for (let i = 0; i < N; i++) {
        const v = x[i];
        x[i] = IT[0][S[0][byte(v)]] ^
            IT[1][S[1][byte(v >> 8n)]] ^
            IT[2][S[2][byte(v >> 16n)]] ^
            IT[3][S[3][byte(v >> 24n)]] ^
            IT[4][S[0][byte(v >> 32n)]] ^
            IT[5][S[1][byte(v >> 40n)]] ^
            IT[6][S[2][byte(v >> 48n)]] ^
            IT[7][S[3][byte(v >> 56n)]];
    }
}

export const IG = (x: BigUint64Array, y: BigUint64Array, k: BigUint64Array, N: number) => {
    for (let i = 0; i < N; i++) {
        let result = k[i];
        for (let j = 0; j < 8; j++) {
            const wordOffset = N === 8 ? j : N === 4 ? Math.floor(j / 2) : Math.floor(j / 4);
            result ^= IT[j][byte(x[(i + wordOffset) % N] >> BigInt(j * 8))];
        }
        y[i] = result;
    }
}

export const IGL = (x: BigUint64Array, y: BigUint64Array, k: BigUint64Array, N: number) => {
    for (let i = 0; i < N; i++) {
        let result = 0n;
        for (let j = 0; j < 8; j++) {
            const wordOffset = N === 8 ? j : N === 4 ? Math.floor(j / 2) : Math.floor(j / 4);
            const shift = BigInt(j * 8);
            result ^= BigInt(IS[j % 4][byte(x[(i + wordOffset) % N] >> shift)]) << shift;
        }
        y[i] = result - k[i];
    }
}