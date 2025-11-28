
import { ed25519, ristretto255, ristretto255_hasher } from "@noble/curves/ed25519.js";
import * as mod from "@noble/curves/abstract/modular.js";
import { bytesToNumberLE, numberToBytesLE } from "@noble/curves/utils.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { sha512 } from '@noble/hashes/sha2.js';

import { createOPRF, createPOPRF, createVOPRF, InvalidInputError, InverseError, Suite, type Keypair } from "./_oprf.mjs";
export { Keypair, InvalidInputError, InverseError }; // Reexport important types

// Weird type override to fix RistrettoPoint being a value of type RistPoint
export type Ristretto255Point = InstanceType<typeof ristretto255.Point>;

const suite: Suite<Ristretto255Point> = Object.freeze({
	// Constants
	id: "ristretto255-SHA512",
	curve: ed25519.CURVE,
	point: ristretto255.Point,
	field: mod.Field(ed25519.CURVE.n, undefined, true),
	scalarSize: 32,
	elementSize: 32,
	hash: sha512,
	outputSize: sha512.outputLen,
	// Interface methods
	encodeElement(point: Ristretto255Point): Uint8Array {
		return point.toBytes();
	},
	decodeElement(bytes: Uint8Array): Ristretto255Point {
		return ristretto255.Point.fromBytes(bytes);
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
		return ristretto255_hasher.hashToScalar(msg, { DST: dst });
	},
	hashToGroup(msg: Uint8Array, dst: Uint8Array): Ristretto255Point {
		return ristretto255_hasher.hashToCurve(msg, { DST: dst }) as Ristretto255Point;
	},
});

export const OPRF = createOPRF(suite);
export const VOPRF = createVOPRF(suite);
export const POPRF = createPOPRF(suite);
