import { describe, test, expect } from "bun:test";
import { Kalyna128, Kalyna128_256, Kalyna256, Kalyna256_512, Kalyna512, encryptECB, decryptECB } from "../src";
import { hexToBytes } from "@li0ard/gost3413/dist/utils";

describe("ECB", () => {
    test("128/128", () => {
        let a = new Kalyna128(hexToBytes("000102030405060708090A0B0C0D0E0F"));
        let pt = hexToBytes("101112131415161718191A1B1C1D1E1F");
        let ct = hexToBytes("81BF1C7D779BAC20E1C9EA39B4D2AD06");

        expect(encryptECB(a, pt)).toStrictEqual(ct);
        expect(decryptECB(a, ct)).toStrictEqual(pt);
    })
    test("128/256", () => {
        let a = new Kalyna128_256(hexToBytes("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"));
        let pt = hexToBytes("202122232425262728292A2B2C2D2E2F");
        let ct = hexToBytes("58EC3E091000158A1148F7166F334F14");

        expect(encryptECB(a, pt)).toStrictEqual(ct);
        expect(decryptECB(a, ct)).toStrictEqual(pt);
    })

    test("256/256", () => {
        let a = new Kalyna256(hexToBytes("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"));
        let pt = hexToBytes("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");
        let ct = hexToBytes("F66E3D570EC92135AEDAE323DCBD2A8CA03963EC206A0D5A88385C24617FD92C");

        expect(encryptECB(a, pt)).toStrictEqual(ct);
        expect(decryptECB(a, ct)).toStrictEqual(pt);
    })
    test("256/512", () => {
        let a = new Kalyna256_512(hexToBytes("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"));
        let pt = hexToBytes("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");
        let ct = hexToBytes("606990E9E6B7B67A4BD6D893D72268B78E02C83C3CD7E102FD2E74A8FDFE5DD9");

        expect(encryptECB(a, pt)).toStrictEqual(ct);
        expect(decryptECB(a, ct)).toStrictEqual(pt);
    })

    test("512", () => {
        let a = new Kalyna512(hexToBytes("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"));
        let pt = hexToBytes("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F");
        let ct = hexToBytes("4A26E31B811C356AA61DD6CA0596231A67BA8354AA47F3A13E1DEEC320EB56B895D0F417175BAB662FD6F134BB15C86CCB906A26856EFEB7C5BC6472940DD9D9");

        expect(encryptECB(a, pt)).toStrictEqual(ct);
        expect(decryptECB(a, ct)).toStrictEqual(pt);
    })
})
