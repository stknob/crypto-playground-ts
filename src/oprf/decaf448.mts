
import { ed448, decaf448, decaf448_hasher } from "@noble/curves/ed448.js";
import * as mod from "@noble/curves/abstract/modular.js";
import { bytesToNumberLE, numberToBytesLE } from "@noble/curves/utils.js";
import { randomBytes} from "@noble/hashes/utils.js";
import { shake256_64 } from "@noble/hashes/sha3.js";

import { createOPRF, createPOPRF, createVOPRF, InvalidInputError, InverseError, Suite, type Keypair } from "./_oprf.mjs";
export { Keypair, InvalidInputError, InverseError }; // Reexport important types

// Weird type override to fix RistrettoPoint being a value of type RistPoint
export type Decaf448Point = InstanceType<typeof decaf448.Point>;
export type Ed448Curve = ReturnType<typeof ed448.Point.CURVE>;

const suite: Suite<Decaf448Point> = Object.freeze({
	// Constants
	id: "decaf448-SHAKE256",
	point: decaf448.Point,
	field: decaf448.Point.Fn,
	scalarSize: 56,
	elementSize: 56,
	hash: shake256_64,
	outputSize: shake256_64.outputLen,
	// Interface methods
	encodeElement(point: Decaf448Point): Uint8Array {
		return point.toBytes();
	},
	decodeElement(bytes: Uint8Array): Decaf448Point {
		return decaf448.Point.fromBytes(bytes);
	},
	randomScalar(): bigint {
		const uniform_random = randomBytes(this.scalarSize * 2);
		return this.decodeScalar(mod.mapHashToField(uniform_random, ed448.Point.CURVE().n, true));
	},
	encodeScalar(scalar: bigint): Uint8Array {
		return numberToBytesLE(scalar, this.scalarSize);
	},
	decodeScalar(bytes: Uint8Array): bigint {
		const val = bytesToNumberLE(bytes);
		if (!this.field.isValid(val)) throw new InvalidInputError();
		return val;
	},
	hashToScalar(msg: Uint8Array, DST: Uint8Array): bigint {
		return decaf448_hasher.hashToScalar(msg, { DST });
	},
	hashToGroup(msg: Uint8Array, DST: Uint8Array): Decaf448Point {
		return decaf448_hasher.hashToCurve(msg, { DST }) as Decaf448Point;
	},
});

export const OPRF = (() => createOPRF(suite))();
export const VOPRF = (() => createVOPRF(suite))();
export const POPRF = (() => createPOPRF(suite))();
