import { p256, p256_hasher } from "@noble/curves/nist.js";
import * as mod from "@noble/curves/abstract/modular.js";
import { numberToBytesBE } from "@noble/curves/utils.js";
import { sha256 } from '@noble/hashes/sha2.js';

import { createOPRF, createPOPRF, createVOPRF, InvalidInputError, InverseError, Suite, type Keypair } from "./_oprf.mjs";
export { Keypair, InvalidInputError, InverseError }; // Reexport important types

// Weird type override to fix RistrettoPoint being a value of type RistPoint
export type secp256r1Point = InstanceType<typeof p256.Point>;

const secp256r1Suite: Suite<secp256r1Point> = Object.freeze({
	id: "P256-SHA256",
	curve: p256.CURVE,
	point: p256.Point,
	field: mod.Field(p256.CURVE.n, undefined, false),
	elementSize: 33,
	scalarSize: 32,
	hash: sha256,
	outputSize: 32,
	// Interface methods
	encodeElement(point: secp256r1Point): Uint8Array {
		return point.toBytes();
	},
	decodeElement(bytes: Uint8Array): secp256r1Point {
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
	hashToScalar(msg: Uint8Array, dst: Uint8Array): bigint {
		return p256_hasher.hashToScalar(msg, { DST: dst });
	},
	hashToGroup(msg: Uint8Array, dst: Uint8Array): secp256r1Point {
		return p256_hasher.hashToCurve(msg, { DST: dst }) as secp256r1Point;
	},
});

export const OPRF = createOPRF(secp256r1Suite);
export const VOPRF = createVOPRF(secp256r1Suite);
export const POPRF = createPOPRF(secp256r1Suite);
