import { p384, p384_hasher } from "@noble/curves/nist.js";
import * as mod from "@noble/curves/abstract/modular.js";
import { numberToBytesBE } from "@noble/curves/utils.js";
import { sha384 } from '@noble/hashes/sha2.js';

import { createOPRF, createPOPRF, createVOPRF, InvalidInputError, InverseError, Suite, type Keypair } from "./_oprf.mjs";
export { Keypair, InvalidInputError, InverseError }; // Reexport important types

// Weird type override to fix RistrettoPoint being a value of type RistPoint
export type P384Point = InstanceType<typeof p384.Point>;
export type P384Curve = ReturnType<typeof p384.Point.CURVE>;

const suite: Suite<P384Point> = Object.freeze({
	id: "P384-SHA384",
	point: p384.Point,
	field: mod.Field(p384.Point.CURVE().n, undefined, false),
	elementSize: 49,
	scalarSize: 48,
	hash: sha384,
	outputSize: 48,
	// Interface methods
	encodeElement(point: P384Point): Uint8Array {
		return point.toBytes();
	},
	decodeElement(bytes: Uint8Array): P384Point {
		return p384.Point.fromBytes(bytes);
	},
	randomScalar(): bigint {
		const tmp = p384.utils.randomSecretKey();
		return p384.Point.Fn.fromBytes(tmp);
	},
	encodeScalar(scalar: bigint): Uint8Array {
		return numberToBytesBE(scalar, this.scalarSize);
	},
	decodeScalar(bytes: Uint8Array): bigint {
		return p384.Point.Fn.fromBytes(bytes);
	},
	hashToScalar(msg: Uint8Array, DST: Uint8Array): bigint {
		return p384_hasher.hashToScalar(msg, { DST });
	},
	hashToGroup(msg: Uint8Array, DST: Uint8Array): P384Point {
		return p384_hasher.hashToCurve(msg, { DST }) as P384Point;
	},
});

export const OPRF = (() => createOPRF(suite))();
export const VOPRF = (() => createVOPRF(suite))();
export const POPRF = (() => createPOPRF(suite))();
