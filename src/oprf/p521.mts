import { secp521r1, hashToCurve } from "@noble/curves/p521";
import * as mod from "@noble/curves/abstract/modular.js";
import { numberToBytesBE } from "@noble/curves/abstract/utils.js";
import { hash_to_field } from "@noble/curves/abstract/hash-to-curve.js";
import { sha512 } from '@noble/hashes/sha2.js';

import { createOPRF, createPOPRF, createVOPRF, InvalidInputError, InverseError, Suite, type Keypair } from "./_oprf.mjs";
export { Keypair, InvalidInputError, InverseError }; // Reexport important types

// Weird type override to fix RistrettoPoint being a value of type RistPoint
export type secp521r1Point = InstanceType<typeof secp521r1.ProjectivePoint>;

const secp521r1Suite: Suite<secp521r1Point> = Object.freeze({
	id: "P521-SHA512",
	curve: secp521r1.CURVE,
	point: secp521r1.ProjectivePoint,
	field: mod.Field(secp521r1.CURVE.n, undefined, false),
	elementSize: 67,
	scalarSize: 66,
	hash: sha512,
	outputSize: 64,
	// Interface methods
	encodeElement(point: secp521r1Point): Uint8Array {
		return point.toRawBytes();
	},
	decodeElement(bytes: Uint8Array): secp521r1Point {
		return secp521r1.ProjectivePoint.fromHex(bytes);
	},
	randomScalar(): bigint {
		const tmp = secp521r1.utils.randomPrivateKey();
		return secp521r1.utils.normPrivateKeyToScalar(tmp);
	},
	encodeScalar(scalar: bigint): Uint8Array {
		return numberToBytesBE(scalar, this.scalarSize);
	},
	decodeScalar(bytes: Uint8Array): bigint {
		return secp521r1.utils.normPrivateKeyToScalar(bytes);
	},
	hashToScalar(msg: Uint8Array, dst: Uint8Array): bigint {
		const res = hash_to_field(msg, 1, { DST: dst, hash: this.hash, p: this.curve.n, expand: "xmd", m: 1, k: 256 });
		return res[0][0];
	},
	hashToGroup(msg: Uint8Array, dst: Uint8Array): secp521r1Point {
		const affinePoint = hashToCurve(msg, { DST: dst }).toAffine();
		return secp521r1.ProjectivePoint.fromAffine(affinePoint);
	},
});

export const OPRF = createOPRF(secp521r1Suite);
export const VOPRF = createVOPRF(secp521r1Suite);
export const POPRF = createPOPRF(secp521r1Suite);
