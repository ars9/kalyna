import { describe, test, expect } from "bun:test";
import { Kalyna128, Kalyna128_256, Kalyna256, Kalyna256_512, Kalyna512, encryptCFB, decryptCFB } from "../src";
import { hexToBytes } from "@li0ard/gost3413/dist/utils";

describe("CFB", () => {
    test("128/128", () => {
        let a = new Kalyna128(hexToBytes("000102030405060708090A0B0C0D0E0F"));
        let iv = hexToBytes("101112131415161718191A1B1C1D1E1F");
        let pt = hexToBytes("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F");
        let ct = hexToBytes("a19e3e5e53be8a07c9e0c01298ff83291f8ee6212110be3fa5c72c88a082520b265570fe28680719d9b4465e169bc37a");

        expect(encryptCFB(a, pt, iv)).toStrictEqual(ct);
        expect(decryptCFB(a, ct, iv)).toStrictEqual(pt);
    })
})