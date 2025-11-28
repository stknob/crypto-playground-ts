import { p521, p521_hasher } from "@noble/curves/nist.js";
import * as mod from "@noble/curves/abstract/modular.js";
import { numberToBytesBE } from "@noble/curves/utils.js";
import { sha512 } from '@noble/hashes/sha2.js';

import { createOPRF, createPOPRF, createVOPRF, InvalidInputError, InverseError, Suite, type Keypair } from "./_oprf.mjs";
export { Keypair, InvalidInputError, InverseError }; // Reexport important types

// Weird type override to fix RistrettoPoint being a value of type RistPoint
export type secp521r1Point = InstanceType<typeof p521.Point>;

const secp521r1Suite: Suite<secp521r1Point> = Object.freeze({
	id: "P521-SHA512",
	curve: p521.CURVE,
	point: p521.Point,
	field: mod.Field(p521.CURVE.n, undefined, false),
	elementSize: 67,
	scalarSize: 66,
	hash: sha512,
	outputSize: 64,
	// Interface methods
	encodeElement(point: secp521r1Point): Uint8Array {
		return point.toBytes();
	},
	decodeElement(bytes: Uint8Array): secp521r1Point {
		return p521.Point.fromHex(bytes);
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
	hashToScalar(msg: Uint8Array, dst: Uint8Array): bigint {
		return p521_hasher.hashToScalar(msg, { DST: dst });
	},
	hashToGroup(msg: Uint8Array, dst: Uint8Array): secp521r1Point {
		return p521_hasher.hashToCurve(msg, { DST: dst }) as secp521r1Point;
	},
});

export const OPRF = createOPRF(secp521r1Suite);
export const VOPRF = createVOPRF(secp521r1Suite);
export const POPRF = createPOPRF(secp521r1Suite);
