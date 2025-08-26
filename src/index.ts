import { KalynaBase } from "./core";

/** Kalyna 128 bit version */
export class Kalyna128 extends KalynaBase {
    constructor(key: Uint8Array) { super(key, 2); }
}
/** Kalyna 128/256 bit version */
export class Kalyna128_256 extends KalynaBase {
    constructor(key: Uint8Array) { super(key, 2, true); }
}

/** Kalyna 256 bit version */
export class Kalyna256 extends KalynaBase {
    constructor(key: Uint8Array) { super(key, 4); }
}
/** Kalyna 256/512 bit version */
export class Kalyna256_512 extends KalynaBase {
    constructor(key: Uint8Array) { super(key, 4, true); }
}

/** Kalyna 512 bit version */
export class Kalyna512 extends KalynaBase {
    constructor(key: Uint8Array) { super(key, 8); }
}

export * from "./padding";
export * from "./modes/ecb";
export * from "./modes/cbc";
export * from "./modes/ofb";
export * from "./modes/ctr";
export * from "./modes/mac";
export * from "./modes/cfb";
export * from "./modes/ccm";
export * from "./modes/gcm";
export * from "./modes/kw";
export * from "./modes/xts";