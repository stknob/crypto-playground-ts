import { p384, p384_hasher } from "@noble/curves/nist.js";
import * as mod from "@noble/curves/abstract/modular.js";
import { numberToBytesBE } from "@noble/curves/utils.js";
import { hash_to_field } from "@noble/curves/abstract/hash-to-curve.js";
import { sha384 } from '@noble/hashes/sha2.js';

import { createOPRF, createPOPRF, createVOPRF, InvalidInputError, InverseError, Suite, type Keypair } from "./_oprf.mjs";
export { Keypair, InvalidInputError, InverseError }; // Reexport important types

// Weird type override to fix RistrettoPoint being a value of type RistPoint
export type secp384r1Point = InstanceType<typeof p384.Point>;

const secp384r1Suite: Suite<secp384r1Point> = Object.freeze({
	id: "P384-SHA384",
	curve: p384.CURVE,
	point: p384.Point,
	field: mod.Field(p384.CURVE.n, undefined, false),
	elementSize: 49,
	scalarSize: 48,
	hash: sha384,
	outputSize: 48,
	// Interface methods
	encodeElement(point: secp384r1Point): Uint8Array {
		return point.toBytes();
	},
	decodeElement(bytes: Uint8Array): secp384r1Point {
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
	hashToScalar(msg: Uint8Array, dst: Uint8Array): bigint {
		const res = hash_to_field(msg, 1, { DST: dst, hash: this.hash, p: this.curve.n, expand: "xmd", m: 1, k: 192 });
		return res[0][0];
	},
	hashToGroup(msg: Uint8Array, dst: Uint8Array): secp384r1Point {
		const affinePoint = p384_hasher.hashToCurve(msg, { DST: dst }).toAffine();
		return p384.Point.fromAffine(affinePoint);
	},
});

export const OPRF = createOPRF(secp384r1Suite);
export const VOPRF = createVOPRF(secp384r1Suite);
export const POPRF = createPOPRF(secp384r1Suite);
