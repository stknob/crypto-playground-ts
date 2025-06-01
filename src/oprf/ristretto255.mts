
import { ed25519, RistrettoPoint } from "@noble/curves/ed25519.js";
import * as mod from "@noble/curves/abstract/modular.js";
import { bytesToNumberLE, numberToBytesLE } from "@noble/curves/abstract/utils.js";
import { expand_message_xmd } from "@noble/curves/abstract/hash-to-curve.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { sha512 } from '@noble/hashes/sha2.js';

import { createOPRF, createPOPRF, createVOPRF, InvalidInputError, InverseError, Suite, type Keypair } from "./_oprf.mjs";
export { Keypair, InvalidInputError, InverseError }; // Reexport important types

// Weird type override to fix RistrettoPoint being a value of type RistPoint
export type Ristretto255Point = InstanceType<typeof RistrettoPoint>;

const suite: Suite<Ristretto255Point> = Object.freeze({
    // Constants
    id: "ristretto255-SHA512",
    curve: ed25519.CURVE,
    point: RistrettoPoint,
    field: mod.Field(ed25519.CURVE.n, undefined, true),
    scalarSize: 32,
    elementSize: 32,
    hash: sha512,
    outputSize: sha512.outputLen,
    // Interface methods
    encodeElement(point: Ristretto255Point): Uint8Array {
        return point.toRawBytes();
    },
    decodeElement(bytes: Uint8Array): Ristretto255Point {
        return RistrettoPoint.fromHex(bytes);
    },
    randomScalar(): bigint {
        const uniform_random = randomBytes(this.outputSize);	// (outputSize = scalarSize x 2)
		return this.decodeScalar(mod.mapHashToField(uniform_random, this.curve.n, true));
    },
    encodeScalar(scalar: bigint): Uint8Array {
        const tmp = numberToBytesLE(scalar, this.scalarSize);
        const high_bit = tmp[tmp.length - 1] >>> 7;
        if (high_bit) throw new InvalidInputError();
        return tmp;
    },
    decodeScalar(bytes: Uint8Array): bigint {
        const val = bytesToNumberLE(bytes);
        if (!this.field.isValid(val)) throw new InvalidInputError();
        return val;
    },
    hashToScalar(msg: Uint8Array, dst: Uint8Array): bigint {
        const uniform_bytes = expand_message_xmd(msg, dst, this.outputSize, this.hash);
        return this.field.create(bytesToNumberLE(uniform_bytes));
    },
    hashToGroup(msg: Uint8Array, dst: Uint8Array): Ristretto255Point {
        const uniform_bytes = expand_message_xmd(msg, dst, this.outputSize, this.hash);
        return RistrettoPoint.hashToCurve(uniform_bytes);
    },
});

export const OPRF = createOPRF(suite);
export const VOPRF = createVOPRF(suite);
export const POPRF = createPOPRF(suite);
