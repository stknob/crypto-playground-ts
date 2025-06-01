import { secp256r1, hashToCurve } from "@noble/curves/p256";
import * as mod from "@noble/curves/abstract/modular.js";
import { numberToBytesBE } from "@noble/curves/abstract/utils.js";
import { hash_to_field } from "@noble/curves/abstract/hash-to-curve.js";
import { sha256 } from '@noble/hashes/sha2.js';

import { createOPRF, createPOPRF, createVOPRF, InvalidInputError, InverseError, Suite, type Keypair } from "./_oprf.mjs";
export { Keypair, InvalidInputError, InverseError }; // Reexport important types

// Weird type override to fix RistrettoPoint being a value of type RistPoint
export type secp256r1Point = InstanceType<typeof secp256r1.ProjectivePoint>;

const secp256r1Suite: Suite<secp256r1Point> = Object.freeze({
	id: "P256-SHA256",
	curve: secp256r1.CURVE,
	point: secp256r1.ProjectivePoint,
	field: mod.Field(secp256r1.CURVE.n, undefined, false),
	elementSize: 33,
	scalarSize: 32,
	hash: sha256,
	outputSize: 32,
	// Interface methods
	encodeElement(point: secp256r1Point): Uint8Array {
		return point.toRawBytes();
	},
	decodeElement(bytes: Uint8Array): secp256r1Point {
		return secp256r1.ProjectivePoint.fromHex(bytes);
	},
	randomScalar(): bigint {
		const tmp = secp256r1.utils.randomPrivateKey();
		return secp256r1.utils.normPrivateKeyToScalar(tmp);
	},
	encodeScalar(scalar: bigint): Uint8Array {
		return numberToBytesBE(scalar, this.scalarSize);
	},
	decodeScalar(bytes: Uint8Array): bigint {
		return secp256r1.utils.normPrivateKeyToScalar(bytes);
	},
	hashToScalar(msg: Uint8Array, dst: Uint8Array): bigint {
		const res = hash_to_field(msg, 1, { DST: dst, hash: this.hash, p: this.curve.n, expand: "xmd", m: 1, k: 128 });
		return res[0][0];
	},
	hashToGroup(msg: Uint8Array, dst: Uint8Array): secp256r1Point {
		const affinePoint = hashToCurve(msg, { DST: dst }).toAffine();
		return secp256r1.ProjectivePoint.fromAffine(affinePoint);
	},
});

export const OPRF = createOPRF(secp256r1Suite);
export const VOPRF = createVOPRF(secp256r1Suite);
export const POPRF = createPOPRF(secp256r1Suite);
