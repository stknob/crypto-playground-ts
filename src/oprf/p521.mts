import { p521, p521_hasher } from "@noble/curves/nist.js";
import * as mod from "@noble/curves/abstract/modular.js";
import { numberToBytesBE } from "@noble/curves/utils.js";
import { sha512 } from '@noble/hashes/sha2.js';

import { createOPRF, createPOPRF, createVOPRF, InvalidInputError, InverseError, Suite, type Keypair } from "./_oprf.mjs";
export { Keypair, InvalidInputError, InverseError }; // Reexport important types

// Weird type override to fix RistrettoPoint being a value of type RistPoint
export type P521Point = InstanceType<typeof p521.Point>;
export type P521Curve = ReturnType<typeof p521.Point.CURVE>;

const suite: Suite<P521Point> = Object.freeze({
	id: "P521-SHA512",
	point: p521.Point,
	field: mod.Field(p521.Point.CURVE().n, undefined, false),
	elementSize: 67,
	scalarSize: 66,
	hash: sha512,
	outputSize: 64,
	// Interface methods
	encodeElement(point: P521Point): Uint8Array {
		return point.toBytes();
	},
	decodeElement(bytes: Uint8Array): P521Point {
		return p521.Point.fromBytes(bytes);
	},
	randomScalar(): bigint {
		const tmp = p521.utils.randomSecretKey();
		return p521.Point.Fn.fromBytes(tmp);
	},
	encodeScalar(scalar: bigint): Uint8Array {
		return numberToBytesBE(scalar, this.scalarSize);
	},
	decodeScalar(bytes: Uint8Array): bigint {
		return p521.Point.Fn.fromBytes(bytes);
	},
	hashToScalar(msg: Uint8Array, DST: Uint8Array): bigint {
		return p521_hasher.hashToScalar(msg, { DST });
	},
	hashToGroup(msg: Uint8Array, DST: Uint8Array): P521Point {
		return p521_hasher.hashToCurve(msg, { DST }) as P521Point;
	},
});

export const OPRF = (() => createOPRF(suite))();
export const VOPRF = (() => createVOPRF(suite))();
export const POPRF = (() => createPOPRF(suite))();
