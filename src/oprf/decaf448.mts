
import { ed448, decaf448, decaf448_hasher } from "@noble/curves/ed448.js";
import * as mod from "@noble/curves/abstract/modular.js";
import { bytesToNumberLE, numberToBytesLE } from "@noble/curves/utils.js";
import { HashXOF, randomBytes, wrapConstructor } from "@noble/hashes/utils.js";
import { shake256 } from "@noble/hashes/sha3.js";

import { createOPRF, createPOPRF, createVOPRF, InvalidInputError, InverseError, Suite, type Keypair } from "./_oprf.mjs";
export { Keypair, InvalidInputError, InverseError }; // Reexport important types

// Weird type override to fix RistrettoPoint being a value of type RistPoint
export type Decaf448Point = InstanceType<typeof decaf448.Point>;

const shake256_512 = wrapConstructor<HashXOF<any>>(() => shake256.create({ dkLen: 64 }));

const suite: Suite<Decaf448Point> = Object.freeze({
	// Constants
	id: "decaf448-SHAKE256",
	curve: ed448.CURVE,
	point: decaf448.Point,
	field: mod.Field(ed448.CURVE.n, undefined, true),
	scalarSize: 56,
	elementSize: 56,
	hash: shake256_512,
	outputSize: shake256_512.outputLen,
	// Interface methods
	encodeElement(point: Decaf448Point): Uint8Array {
		return point.toBytes();
	},
	decodeElement(bytes: Uint8Array): Decaf448Point {
		return decaf448.Point.fromBytes(bytes);
	},
	randomScalar(): bigint {
		const uniform_random = randomBytes(this.scalarSize * 2);
		return this.decodeScalar(mod.mapHashToField(uniform_random, this.curve.n, true));
	},
	encodeScalar(scalar: bigint): Uint8Array {
		return numberToBytesLE(scalar, this.scalarSize);
	},
	decodeScalar(bytes: Uint8Array): bigint {
		const val = bytesToNumberLE(bytes);
		if (!this.field.isValid(val)) throw new InvalidInputError();
		return val;
	},
	hashToScalar(msg: Uint8Array, dst: Uint8Array): bigint {
		return decaf448_hasher.hashToScalar(msg, { DST: dst });
	},
	hashToGroup(msg: Uint8Array, dst: Uint8Array): Decaf448Point {
		return decaf448_hasher.hashToCurve(msg, { DST: dst }) as Decaf448Point;
	},
});

export const OPRF = createOPRF(suite);
export const VOPRF = createVOPRF(suite);
export const POPRF = createPOPRF(suite);
