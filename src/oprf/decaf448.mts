
import { ed448, DecafPoint, hashToDecaf448 } from "@noble/curves/ed448.js";
import * as mod from "@noble/curves/abstract/modular.js";
import { bytesToNumberLE, numberToBytesLE } from "@noble/curves/abstract/utils.js";
import { expand_message_xof, hash_to_field } from "@noble/curves/abstract/hash-to-curve.js";
import { HashXOF, randomBytes, wrapConstructor } from "@noble/hashes/utils.js";
import { shake256 } from "@noble/hashes/sha3";

import { createOPRF, createPOPRF, createVOPRF, InvalidInputError, InverseError, Suite, type Keypair } from "./_oprf.mjs";
export { Keypair, InvalidInputError, InverseError }; // Reexport important types

// Weird type override to fix RistrettoPoint being a value of type RistPoint
export type Decaf448Point = InstanceType<typeof DecafPoint>;

const shake256_512 = wrapConstructor<HashXOF<any>>(() => shake256.create({ dkLen: 64 }));

const suite: Suite<Decaf448Point> = Object.freeze({
	// Constants
	id: "decaf448-SHAKE256",
	curve: ed448.CURVE,
	point: DecafPoint,
	field: mod.Field(ed448.CURVE.n, undefined, true),
	scalarSize: 56,
	elementSize: 56,
	hash: shake256_512,
	outputSize: shake256_512.outputLen,
	// Interface methods
	encodeElement(point: Decaf448Point): Uint8Array {
		return point.toRawBytes();
	},
	decodeElement(bytes: Uint8Array): Decaf448Point {
		return DecafPoint.fromHex(bytes);
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
		const uniform_bytes = expand_message_xof(msg, dst, this.outputSize, 448, this.hash);
		return this.field.create(bytesToNumberLE(uniform_bytes));
	},
	hashToGroup(msg: Uint8Array, dst: Uint8Array): Decaf448Point {
		return hashToDecaf448(msg, { DST: dst });
	},
});

export const OPRF = createOPRF(suite);
export const VOPRF = createVOPRF(suite);
export const POPRF = createPOPRF(suite);
