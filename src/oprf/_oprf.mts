import * as mod from "@noble/curves/abstract/modular.js";
import { BasicCurve, Group, GroupConstructor } from "@noble/curves/abstract/curve.js";

import { CHash, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { abytes } from "@noble/curves/abstract/utils.js";

import { I2OSP, splitBytesShared } from "./_utils.mjs";

/**
 * Oblivious Pseudorandom Functions (OPRFs) using Prime-Order Groups
 * https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-13
 */
const EMPTY_BUFFER = /* @__PURE__ */ Uint8Array.of();

const Mode = Object.freeze({
	OPRF:  0x00,
	VOPRF: 0x01,
	POPRF: 0x02,
});

const Labels = Object.freeze({
	ContextV1Prefix: utf8ToBytes("OPRFV1-"),
	Finalize: utf8ToBytes("Finalize"),
	Challenge: utf8ToBytes("Challenge"),
	Composite: utf8ToBytes("Composite"),
	HashToScalar: utf8ToBytes("HashToScalar-"),
	HashToGroup: utf8ToBytes("HashToGroup-"),
	DeriveKeyPair: utf8ToBytes("DeriveKeyPair"),
	Seed: utf8ToBytes("Seed-"),
	Info: utf8ToBytes("Info"),
});


export class OPRFError extends Error {}
export class InvalidInputError extends OPRFError {}
export class InverseError extends OPRFError {}

export class VerifyError extends OPRFError {
	constructor() { super("Proof verification failed"); }
}

export class DeriveKeyError extends OPRFError {
	constructor() { super("Failed to derive OPRF key pair"); }
}

export type BlindOptions = {
	blindRandomScalar?: bigint,
};

export type GenerateProofOptions = {
	proofRandomScalar?: bigint,
};

export interface Suite<E extends Group<E>> {
	id: string,
	point: GroupConstructor<E>,
	curve: BasicCurve<bigint>,
	field: mod.IField<bigint>,
	scalarSize: number,
	elementSize: number,
	hash: CHash,
	outputSize: number,
	// Group Elements
	hashToGroup(msg: Uint8Array, customDst?: Uint8Array): E,
	encodeElement(point: E): Uint8Array,
	decodeElement(bytes: Uint8Array): E,
	// Scalar
	randomScalar(): bigint,
	hashToScalar(msg: Uint8Array, customDst?: Uint8Array): bigint,
	encodeScalar(scalar: bigint): Uint8Array,
	decodeScalar(bytes: Uint8Array): bigint,
}

export interface Keypair {
	secretKey: Uint8Array,
	publicKey: Uint8Array,
}

interface OPRFPrivate<E extends Group<E>> {
	suite: Readonly<Suite<E>>,
	contextString: Uint8Array,
	hashToGroup(msg: Uint8Array, customDst?: Uint8Array): E,
	hashToScalar(msg: Uint8Array, customDst?: Uint8Array): bigint,
}

interface OPRFCommon<E extends Group<E>> extends OPRFPrivate<E> {
	// Suite convenience accessors
	randomScalar(): bigint,
	encodeScalar(scalar: bigint): Uint8Array,
	decodeScalar(bytes: Uint8Array): bigint,
	encodeElement(element: E): Uint8Array,
	decodeElement(bytes: Uint8Array): E,
	// (V|P)OPRF common methods
	randomKeypair(): Keypair,
	deriveKeypair(seed: Uint8Array, info?: Uint8Array): Keypair,
}

export interface OPRF<E extends Group<E>> extends OPRFCommon<E> {
	blind(input: Uint8Array, options?: BlindOptions): Readonly<{ blind: bigint, blindedElement: E }>,
	blindEvaluate(secretKey: Uint8Array, blindedElement: E): E,
	finalize(input: Uint8Array, blind: bigint, evaluatedElement: E): Uint8Array,
	evaluate(secretKey: Uint8Array, input: Uint8Array): Uint8Array,
}

function encodeProof<T extends Group<T>>(oprf: OPRFPrivate<T>, proof: bigint[]): Uint8Array {
	return concatBytes(...proof.map((v) => oprf.suite.encodeScalar(v)));
}

function decodeProof<T extends Group<T>>(oprf: OPRFPrivate<T>, proof: Uint8Array): bigint[] {
	return splitBytesShared(proof, oprf.suite.scalarSize)
		.map((v) => oprf.suite.decodeScalar(v));
}

/**
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-13#section-2.2.2
 * @param pkS Ristretto255 server public key ("B")
 * @param C blindedElements
 * @param D evaluatedElements
 * @returns
 */
function computeComposites<T extends Group<T>>(oprf: OPRFPrivate<T>, B: T, C: T[], D: T[]): Readonly<{ M: T, Z: T }> {
	const Bm = oprf.suite.encodeElement(B);
	const seedDST = concatBytes(Labels.Seed, oprf.contextString);	// seedDST = "Seed-" || contextString
	const seed = oprf.suite.hash(concatBytes(
		I2OSP(Bm.length, 2), Bm,
		I2OSP(seedDST.length, 2), seedDST,
	));

	let M = oprf.suite.point.ZERO;
	let Z = oprf.suite.point.ZERO;
	for (let i = 0; i < C.length; i++) {
		const Ci = oprf.suite.encodeElement(C[i]);
		const Di = oprf.suite.encodeElement(D[i]);
		const di = oprf.hashToScalar(concatBytes(
			I2OSP(seed.length, 2), seed,
			I2OSP(i, 2),
			I2OSP(Ci.length, 2), Ci,
			I2OSP(Di.length, 2), Di,
			Labels.Composite, // "Composite"
		));

		M = C[i].multiply(di).add(M);
		Z = D[i].multiply(di).add(Z);
	}
	return { M, Z };
}

/**
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-13#section-2.2.1
 * @param skS Ristretto255 server secret key ("k")
 * @param pkS Ristretto255 server public key ("B")
 * @param C blindedElements
 * @param D evaluatedElements
 * @returns
 */
function computeCompositesFast<T extends Group<T>>(oprf: OPRFPrivate<T>, k: bigint, B: T, C: T[], D: T[]): Readonly<{ M: T, Z: T }> {
	const Bm = oprf.suite.encodeElement(B);
	const seedDST = concatBytes(Labels.Seed, oprf.contextString);	// seedDST = "Seed-" || contextString
	const seed = oprf.suite.hash(concatBytes(
		I2OSP(Bm.length, 2), Bm,
		I2OSP(seedDST.length, 2), seedDST,
	));

	let M = oprf.suite.point.ZERO;
	for (let i = 0; i < C.length; i++) {
		const Ci = oprf.suite.encodeElement(C[i]);
		const Di = oprf.suite.encodeElement(D[i]);
		const di = oprf.hashToScalar(concatBytes(
			I2OSP(seed.length, 2), seed,
			I2OSP(i, 2),
			I2OSP(Ci.length, 2), Ci,
			I2OSP(Di.length, 2), Di,
			Labels.Composite, // "Composite"
		));

		M = C[i].multiply(di).add(M);
	}

	const Z = M.multiply(k);

	return { M, Z };
}

/**
 * Compute VOPRF proof
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-13#section-2.2.1
 * @param skS Ristretto255 server secret key
 * @param G Ristretto255 base point
 * @param pkS Ristretto255 server public key
 * @param blindedElements
 * @param evaluatedElements
 * @returns
 */
function generateProof<T extends Group<T>>(oprf: OPRFPrivate<T>, k: bigint, A: T, B: T, C: T[], D: T[], options?: GenerateProofOptions): Uint8Array {
	const { M, Z } = computeCompositesFast<T>(oprf, k, B, C, D);

	const r = options?.proofRandomScalar ?? oprf.suite.randomScalar();
	const t2 = A.multiply(r);
	const t3 = M.multiply(r);

	const Bm = oprf.suite.encodeElement(B);
	const a0 = oprf.suite.encodeElement(M);
	const a1 = oprf.suite.encodeElement(Z);
	const a2 = oprf.suite.encodeElement(t2);
	const a3 = oprf.suite.encodeElement(t3);

	const c = oprf.hashToScalar(concatBytes(
		I2OSP(Bm.length, 2), Bm,
		I2OSP(a0.length, 2), a0,
		I2OSP(a1.length, 2), a1,
		I2OSP(a2.length, 2), a2,
		I2OSP(a3.length, 2), a3,
		Labels.Challenge, // "Challenge"
	));

	const s = oprf.suite.field.sub(r, oprf.suite.field.mul(c, k));
	return encodeProof(oprf, [c, s]);
}

/**
 * Validate server-provided VOPRF proof
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-13#section-2.2.2
 * @param pkS Ristretto255 server public key
 * @param blindedElements
 * @param evaluatedElements
 * @param proof
 * @returns
 */
function verifyProof<T extends Group<T>>(oprf: OPRFPrivate<T>, A: T, B: T, C: T[], D: T[], proof: Uint8Array): boolean {
	const { M, Z } = computeComposites<T>(oprf, B, C, D);
	const [ c, s ] = decodeProof(oprf, proof);

	const t2 = A.multiply(s).add(B.multiply(c));
	const t3 = M.multiply(s).add(Z.multiply(c));

	const Bm = oprf.suite.encodeElement(B);
	const a0 = oprf.suite.encodeElement(M);
	const a1 = oprf.suite.encodeElement(Z);
	const a2 = oprf.suite.encodeElement(t2);
	const a3 = oprf.suite.encodeElement(t3);

	const expectedC = oprf.hashToScalar(concatBytes(
		I2OSP(Bm.length, 2), Bm,
		I2OSP(a0.length, 2), a0,
		I2OSP(a1.length, 2), a1,
		I2OSP(a2.length, 2), a2,
		I2OSP(a3.length, 2), a3,
		Labels.Challenge, // "Challenge"
	));

	return expectedC == c;
}

/**
 * RFC9497 - 5.1 Input Limits
 * @param input
 */
function ainput(input: Uint8Array): void {
	abytes(input ?? EMPTY_BUFFER);
	if (input?.length < 0 || input?.length >= 65536)
		throw new InvalidInputError(`Invalid public input size ${input?.length || 0}, must be 0 - 65535 bytes`);
}

function createCommon<T extends Group<T>>(mode: number, suite: Suite<T>): Readonly<OPRFCommon<T>> {
	const contextString: Uint8Array = concatBytes(
		// "OPRFV1-" || I2OSP(mode, 1) || "-" || identifier
		Labels.ContextV1Prefix, I2OSP(mode, 1),
		utf8ToBytes("-" + suite.id),
	);

	return Object.freeze({
		suite,
		contextString,
		randomScalar(): bigint {
			return suite.randomScalar();
		},
		encodeScalar(scalar: bigint): Uint8Array {
			return suite.encodeScalar(scalar);
		},
		decodeScalar(bytes: Uint8Array): bigint {
			return suite.decodeScalar(bytes);
		},
		encodeElement(element: T): Uint8Array {
			return suite.encodeElement(element);
		},
		decodeElement(bytes: Uint8Array): T {
			return suite.decodeElement(bytes);
		},
		hashToGroup(input: Uint8Array, customDST?: Uint8Array): T {
			const dst = customDST ?? concatBytes(Labels.HashToGroup, this.contextString);	// DST = "HashToGroup-" || contextString
			return suite.hashToGroup(input, dst);
		},
		hashToScalar(input: Uint8Array, customDST?: Uint8Array): bigint {
			const dst = customDST ?? concatBytes(Labels.HashToScalar, this.contextString);	// DST = "HashToScalar-" || contextString
			return suite.hashToScalar(input, dst);
		},
		randomKeypair(): Keypair {
			const skS = suite.randomScalar();

			const secretKey = suite.encodeScalar(skS);
			if (secretKey instanceof Uint8Array === false || secretKey.length != suite.scalarSize)
				throw new DeriveKeyError();

			const publicKey = suite.encodeElement(suite.point.BASE.multiply(skS));
			if (publicKey instanceof Uint8Array === false || publicKey.length != suite.elementSize)
				throw new DeriveKeyError();

			return {
				secretKey,
				publicKey,
			};
		},
		deriveKeypair(seed: Uint8Array, info?: Uint8Array): Keypair {
			ainput(info);
			const deriveInput = concatBytes(seed, I2OSP(info?.length ?? 0, 2), info ?? EMPTY_BUFFER);
			const deriveDST = concatBytes(Labels.DeriveKeyPair, this.contextString);	// DST = "DeriveKeyPair" || contextString

			let counter = 0;
			let skS = 0n;
			while (skS === 0n) {
				if (counter > 255) throw new DeriveKeyError();
				skS = suite.hashToScalar(concatBytes(deriveInput, I2OSP(counter, 1)), deriveDST);
				counter++;
			}

			const secretKey = suite.encodeScalar(skS);
			if (secretKey instanceof Uint8Array === false || secretKey.length != suite.scalarSize)
				throw new DeriveKeyError();

			const publicKey = suite.encodeElement(suite.point.BASE.multiply(skS));
			if (publicKey instanceof Uint8Array === false || publicKey.length != suite.elementSize)
				throw new DeriveKeyError();

			return {
				secretKey,
				publicKey,
			};
		},
	});
}

/** */
export function createOPRF<T extends Group<T>>(suite: Suite<T>): Readonly<OPRF<T>> {
	return Object.freeze({
		...createCommon(Mode.OPRF, suite),
		blind(input: Uint8Array, options?: BlindOptions): Readonly<{ blind: bigint, blindedElement: T }> {
			ainput(input);
			const inputElement = this.hashToGroup(input);
			if (suite.curve.Fp.is0(inputElement))
				throw new InvalidInputError();

			const blind = options?.blindRandomScalar ?? suite.randomScalar();
			const blindedElement = inputElement.multiply(blind);

			return {
				blind,
				blindedElement,
			};
		},
		blindEvaluate(secretKey: Uint8Array, blindedElement: T): T {
			const skS = suite.decodeScalar(secretKey);
			return blindedElement.multiply(skS);
		},
		finalize(input: Uint8Array, blind: bigint, evaluatedElement: T): Uint8Array {
			ainput(input);
			const invBlind = suite.field.inv(blind);
			const N = evaluatedElement.multiply(invBlind);
			const unblindedElement = suite.encodeElement(N);

			return suite.hash(concatBytes(
				I2OSP(input.length, 2), input,
				I2OSP(unblindedElement.length, 2), unblindedElement,
				Labels.Finalize, // "Finalize"
			));
		},
		evaluate(secretKey: Uint8Array, input: Uint8Array): Uint8Array {
			ainput(input);
			const inputElement = this.hashToGroup(input);
			if (suite.curve.Fp.is0(inputElement))
				throw new InvalidInputError();

			const skS = suite.decodeScalar(secretKey);
			const evaluatedElement = inputElement.multiply(skS);
			const issuedElement = suite.encodeElement(evaluatedElement);

			return suite.hash(concatBytes(
				I2OSP(input.length, 2), input,
				I2OSP(issuedElement.length, 2), issuedElement,
				Labels.Finalize, // "Finalize"
			));
		},
	});
}

export interface VOPRF<E extends Group<E>> extends OPRFCommon<E> {
	blind(input: Uint8Array, options?: BlindOptions): Readonly<{ blind: bigint, blindedElement: E }>,
	blindEvaluate(secretKey: Uint8Array, publicKey: Uint8Array, blindedElement: E, options?: GenerateProofOptions): Readonly<{ evaluatedElement: E, proof: Uint8Array }>,
	blindEvaluateBatch(secretKey: Uint8Array, publicKey: Uint8Array, blindedElements: E[], options?: GenerateProofOptions): Readonly<{ evaluatedElements: E[], proof: Uint8Array }>,
	finalize(input: Uint8Array, blind: bigint, evaluatedElement: E, blindedElement: E, publicKey: Uint8Array, proof: Uint8Array): Uint8Array,
	finalizeBatch(inputs: Uint8Array[], blinds: bigint[], evaluatedElements: E[], blindedElements: E[], publicKey: Uint8Array, proof: Uint8Array): Uint8Array[],
	evaluate(secretKey: Uint8Array, input: Uint8Array): Uint8Array,
}

/** */
export function createVOPRF<T extends Group<T>>(suite: Suite<T>): VOPRF<T> {
	return Object.freeze({
		...createCommon(Mode.VOPRF, suite),
		blind(input: Uint8Array, options?: BlindOptions): Readonly<{ blind: bigint, blindedElement: T }> {
			ainput(input);
			const inputElement = this.hashToGroup(input);
			if (suite.curve.Fp.is0(inputElement))
				throw new InvalidInputError();

			const blind = options?.blindRandomScalar ?? suite.randomScalar();
			const blindedElement = inputElement.multiply(blind);

			return {
				blind,
				blindedElement,
			};
		},
		blindEvaluate(secretKey: Uint8Array, publicKey: Uint8Array, blindedElement: T, options?: GenerateProofOptions): Readonly<{ evaluatedElement: T, proof: Uint8Array }> {
			const skS = suite.decodeScalar(secretKey);
			const evaluatedElement = blindedElement.multiply(skS);
			const blindedElements = [ blindedElement ];
			const evaluatedElements = [ evaluatedElement ];

			const pkS = suite.decodeElement(publicKey);
			const proof = generateProof(this, skS, suite.point.BASE, pkS,
				blindedElements, evaluatedElements, options);

			return {
				evaluatedElement,
				proof,
			};
		},
		blindEvaluateBatch(secretKey: Uint8Array, publicKey: Uint8Array, blindedElements: T[], options?: GenerateProofOptions): Readonly<{ evaluatedElements: T[], proof: Uint8Array }> {
			const skS = suite.decodeScalar(secretKey);
			const evaluatedElements = blindedElements.map((blindedElement) => blindedElement.multiply(skS));

			const pkS = suite.decodeElement(publicKey);
			const proof = generateProof(this, skS, suite.point.BASE, pkS,
				blindedElements, evaluatedElements, options);

			return {
				evaluatedElements,
				proof,
			};
		},
		finalize(input: Uint8Array, blind: bigint, evaluatedElement: T, blindedElement: T, publicKey: Uint8Array, proof: Uint8Array): Uint8Array {
			ainput(input);
			const pkS = suite.decodeElement(publicKey);
			const blindedElements = [ blindedElement ];
			const evaluatedElements = [ evaluatedElement ];

			if (!verifyProof(this, suite.point.BASE, pkS, blindedElements, evaluatedElements, proof))
				throw new VerifyError();

			const invBlind = suite.field.inv(blind);
			const N = evaluatedElement.multiply(invBlind);
			const unblindedElement = suite.encodeElement(N);

			return suite.hash(concatBytes(
				I2OSP(input.length, 2), input,
				I2OSP(unblindedElement.length, 2), unblindedElement,
				Labels.Finalize, // "Finalize"
			));
		},
		finalizeBatch(inputs: Uint8Array[], blinds: bigint[], evaluatedElements: T[], blindedElements: T[], publicKey: Uint8Array, proof: Uint8Array): Uint8Array[] {
			const pkS = suite.decodeElement(publicKey);
			if (!verifyProof(this, suite.point.BASE, pkS, blindedElements, evaluatedElements, proof))
				throw new VerifyError();

			const results = [];
			for (let i = 0; i < inputs.length; i++) {
				ainput(inputs[i]);
				const invBlind = suite.field.inv(blinds[i]);
				const N = evaluatedElements[i].multiply(invBlind);
				const unblindedElement = suite.encodeElement(N);

				results.push(suite.hash(concatBytes(
					I2OSP(inputs[i].length, 2), inputs[i],
					I2OSP(unblindedElement.length, 2), unblindedElement,
					Labels.Finalize, // "Finalize"
				)));
			}
			return results;
		},
		evaluate(secretKey: Uint8Array, input: Uint8Array): Uint8Array {
			ainput(input);
			const inputElement = this.hashToGroup(input);
			if (suite.curve.Fp.is0(inputElement))
				throw new InvalidInputError();

			const skS = suite.decodeScalar(secretKey);
			const evaluatedElement = inputElement.multiply(skS);
			const issuedElement = suite.encodeElement(evaluatedElement);

			return suite.hash(concatBytes(
				I2OSP(input.length, 2), input,
				I2OSP(issuedElement.length, 2), issuedElement,
				Labels.Finalize, // "Finalize"
			));
		},
	});
}


export interface POPRF<E extends Group<E>> extends OPRFCommon<E> {
	blind(input: Uint8Array, info: Uint8Array, publicKey: Uint8Array, options?: BlindOptions): Readonly<{ blind: bigint, blindedElement: E, tweakedKey: E }>,
	blindEvaluate(secretKey: Uint8Array, blindedElement: E, info: Uint8Array, options?: GenerateProofOptions): Readonly<{ evaluatedElement: E, proof: Uint8Array }>,
	blindEvaluateBatch(secretKey: Uint8Array, blindedElements: E[], info: Uint8Array, options?: GenerateProofOptions): Readonly<{ evaluatedElements: E[], proof: Uint8Array }>,
	finalize(input: Uint8Array, blind: bigint, evaluatedElement: E, blindedElement: E, proof: Uint8Array, info: Uint8Array, tweakedKey: E): Uint8Array,
	finalizeBatch(inputs: Uint8Array[], blinds: bigint[], evaluatedElements: E[], blindedElements: E[], proof: Uint8Array, info: Uint8Array, tweakedKey: E): Uint8Array[],
	evaluate(secretKey: Uint8Array, input: Uint8Array, info: Uint8Array): Uint8Array,
}

/** */
export function createPOPRF<T extends Group<T>>(suite: Suite<T>): POPRF<T> {
	return Object.freeze({
		...createCommon(Mode.POPRF, suite),
		blind(input: Uint8Array, info: Uint8Array, publicKey: Uint8Array, options?: BlindOptions): Readonly<{ blind: bigint, blindedElement: T, tweakedKey: T }> {
			ainput(input);
			ainput(info);
			const framedInfo = concatBytes(Labels.Info, I2OSP(info?.length ?? 0, 2), info ?? EMPTY_BUFFER);
			const m = this.hashToScalar(framedInfo);
			const pkS = suite.decodeElement(publicKey);
			const tweakedKey = suite.point.BASE.multiply(m).add(pkS);
			if (suite.point.ZERO.equals(tweakedKey))
				throw new InvalidInputError();

			const inputElement = this.hashToGroup(input);
			if (suite.point.ZERO.equals(inputElement))
				throw new InvalidInputError();

			const blind = options?.blindRandomScalar ?? suite.randomScalar();
			const blindedElement = inputElement.multiply(blind);

			return {
				blind,
				blindedElement,
				tweakedKey,
			};
		},
		blindEvaluate(secretKey: Uint8Array, blindedElement: T, info: Uint8Array, options?: GenerateProofOptions): Readonly<{ evaluatedElement: T, proof: Uint8Array }> {
			ainput(info);
			const framedInfo = concatBytes(Labels.Info, I2OSP(info?.length ?? 0, 2), info ?? EMPTY_BUFFER);
			const m = this.hashToScalar(framedInfo);
			const skS = suite.decodeScalar(secretKey);
			const t = suite.field.add(skS, m);
			if (suite.field.is0(t))
				throw new InverseError();

			const evaluatedElement = blindedElement.multiply(suite.field.inv(t));
			const blindedElements = [ blindedElement ];
			const evaluatedElements = [ evaluatedElement ];

			const tweakedKey = suite.point.BASE.multiply(t);
			const proof = generateProof(this, t, suite.point.BASE, tweakedKey,
				evaluatedElements, blindedElements, options);

			return {
				evaluatedElement,
				proof,
			};
		},
		blindEvaluateBatch(secretKey: Uint8Array, blindedElements: T[], info: Uint8Array, options?: GenerateProofOptions): Readonly<{ evaluatedElements: T[], proof: Uint8Array }> {
			ainput(info);
			const framedInfo = concatBytes(Labels.Info, I2OSP(info?.length ?? 0, 2), info ?? EMPTY_BUFFER);
			const m = this.hashToScalar(framedInfo);
			const skS = suite.decodeScalar(secretKey);
			const t = suite.field.add(skS, m);
			if (suite.field.is0(t))
				throw new InverseError();

			const evaluatedElements = blindedElements.map((blindedElement) => blindedElement.multiply(suite.field.inv(t)));

			const tweakedKey = suite.point.BASE.multiply(t);
			const proof = generateProof(this, t, suite.point.BASE, tweakedKey,
				evaluatedElements, blindedElements, options);

			return {
				evaluatedElements,
				proof,
			};
		},
		finalize(input: Uint8Array, blind: bigint, evaluatedElement: T, blindedElement: T, proof: Uint8Array, info: Uint8Array, tweakedKey: T): Uint8Array {
			ainput(input);
			ainput(info);
			const blindedElements = [ blindedElement ];
			const evaluatedElements = [ evaluatedElement ];

			if (!verifyProof(this, suite.point.BASE, tweakedKey, evaluatedElements, blindedElements, proof))
				throw new VerifyError();

			const invBlind = suite.field.inv(blind);
			const N = evaluatedElement.multiply(invBlind);
			const unblindedElement = suite.encodeElement(N);

			return suite.hash(concatBytes(
				I2OSP(input.length, 2), input,
				I2OSP(info?.length ?? 0, 2), info ?? EMPTY_BUFFER,
				I2OSP(unblindedElement.length, 2), unblindedElement,
				Labels.Finalize, // "Finalize"
			));
		},
		finalizeBatch(inputs: Uint8Array[], blinds: bigint[], evaluatedElements: T[], blindedElements: T[], proof: Uint8Array, info: Uint8Array, tweakedKey: T): Uint8Array[] {
			ainput(info);

			if (!verifyProof(this, suite.point.BASE, tweakedKey, evaluatedElements, blindedElements, proof))
				throw new VerifyError();

			const results: Uint8Array[] = [];
			for (let i = 0; i < inputs.length; i++) {
				ainput(inputs[i]);
				const invBlind = suite.field.inv(blinds[i]);
				const N = evaluatedElements[i].multiply(invBlind);
				const unblindedElement = suite.encodeElement(N);

				results.push(suite.hash(concatBytes(
					I2OSP(inputs[i].length, 2), inputs[i],
					I2OSP(info?.length ?? 0, 2), info ?? EMPTY_BUFFER,
					I2OSP(unblindedElement.length, 2), unblindedElement,
					Labels.Finalize, // "Finalize"
				)));
			}
			return results;
		},
		evaluate(secretKey: Uint8Array, input: Uint8Array, info: Uint8Array): Uint8Array {
			ainput(input);
			ainput(info);
			const inputElement = this.hashToGroup(input);
			if (suite.point.ZERO.equals(inputElement))
				throw new InvalidInputError();

			const framedInfo = concatBytes(Labels.Info, I2OSP(info?.length ?? 0, 2), info ?? EMPTY_BUFFER);
			const m = this.hashToScalar(framedInfo);

			const skS = suite.decodeScalar(secretKey);
			const t = suite.field.add(skS, m);
			if (suite.field.is0(t))
				throw new InverseError();

			const evaluatedElement = inputElement.multiply(suite.field.inv(t));
			const issuedElement = suite.encodeElement(evaluatedElement);

			return suite.hash(concatBytes(
				I2OSP(input.length, 2), input,
				I2OSP(info?.length ?? 0, 2), info ?? EMPTY_BUFFER,
				I2OSP(issuedElement.length, 2), issuedElement,
				Labels.Finalize, // "Finalize"
			));
		},
	});
}
