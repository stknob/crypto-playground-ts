import { p256, p256_hasher } from "@noble/curves/nist.js";
import * as mod from "@noble/curves/abstract/modular.js";
import { numberToBytesBE } from "@noble/curves/utils.js";
import { sha256 } from '@noble/hashes/sha2.js';

import { createOPRF, createPOPRF, createVOPRF, InvalidInputError, InverseError, Suite, type Keypair } from "./_oprf.mjs";
export { Keypair, InvalidInputError, InverseError }; // Reexport important types

// Weird type override to fix RistrettoPoint being a value of type RistPoint
export type P256Point = InstanceType<typeof p256.Point>;
export type P256Curve = ReturnType<typeof p256.Point.CURVE>;

const suite: Suite<P256Point> = Object.freeze({
	id: "P256-SHA256",
	point: p256.Point,
	field: mod.Field(p256.Point.CURVE().n, undefined, false),
	elementSize: 33,
	scalarSize: 32,
	hash: sha256,
	outputSize: 32,
	// Interface methods
	encodeElement(point: P256Point): Uint8Array {
		return point.toBytes();
	},
	decodeElement(bytes: Uint8Array): P256Point {
		return p256.Point.fromBytes(bytes);
	},
	randomScalar(): bigint {
		const tmp = p256.utils.randomSecretKey();
		return p256.Point.Fn.fromBytes(tmp);
	},
	encodeScalar(scalar: bigint): Uint8Array {
		return numberToBytesBE(scalar, this.scalarSize);
	},
	decodeScalar(bytes: Uint8Array): bigint {
		return p256.Point.Fn.fromBytes(bytes);
	},
	hashToScalar(msg: Uint8Array, DST: Uint8Array): bigint {
		return p256_hasher.hashToScalar(msg, { DST });
	},
	hashToGroup(msg: Uint8Array, DST: Uint8Array): P256Point {
		return p256_hasher.hashToCurve(msg, { DST }) as P256Point;
	},
});

export const OPRF = (() => createOPRF(suite))();
export const VOPRF = (() => createVOPRF(suite))();
export const POPRF = (() => createPOPRF(suite))();
