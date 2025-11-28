import { expect, use } from 'chai';
import chaibytes from 'chai-bytes';

import { Group } from '@noble/curves/abstract/curve.js';
import { OPRF, VOPRF, POPRF } from "../../../src/oprf/_oprf.mjs";

use(chaibytes);

export type OprfTestVector = {
	seed: Uint8Array,
	name: string,
	keyInfo: Uint8Array,
	skS: Uint8Array,
	blind: Uint8Array,
	input: Uint8Array,
	blindedElement: Uint8Array,
	evaluationElement: Uint8Array,
	output: Uint8Array,
};

export function runOPRFTests<T extends Group<T>>(oprf: OPRF<T>, tests: OprfTestVector[]) {
	for (const test of tests) {
		const keyPair = oprf.deriveKeypair(test.seed, test.keyInfo);
		expect(keyPair.secretKey, `${test.name}: 'secretKey' does not match expected`)
			.to.be.equalBytes(test.skS);

		// Client: Blind
		const blindRandomScalar = oprf.suite.decodeScalar(test.blind);
		const { blind, blindedElement } = oprf.blind(test.input, { blindRandomScalar });
		expect(oprf.suite.encodeScalar(blind), `${test.name}: 'blind' does not match expected`)
			.to.be.equalBytes(test.blind);
		expect(oprf.suite.encodeElement(blindedElement), `${test.name}: 'blindedElement' does not match expected`)
			.to.be.equalBytes(test.blindedElement);

		// Server: BlindEvaluate
		const evaluatedElement = oprf.blindEvaluate(keyPair.secretKey, blindedElement);
		expect(oprf.suite.encodeElement(evaluatedElement), `${test.name}: 'evaluationElement' does not match expected`)
			.to.be.equalBytes(test.evaluationElement);

		// Server: Evaluate (optional)
		const output = oprf.evaluate(keyPair.secretKey, test.input);
		expect(output, `${test.name}: 'evaluate' output does not match expected`)
			.to.be.equalBytes(test.output);

		// Client: Finalize
		const res = oprf.finalize(test.input, blind, evaluatedElement);
		expect(res, `${test.name}: 'finalize' output does not match expected`)
			.to.be.equalBytes(test.output);
	}
}

export type VoprfTestVector = & OprfTestVector & {
	pkS: Uint8Array,
	proof: Uint8Array,
	proofRandomScalar: Uint8Array,
};

export type BatchVoprfTestVector = VoprfTestVector & {
	blind: Uint8Array[],
	input: Uint8Array[],
	blindedElement: Uint8Array[],
	evaluationElement: Uint8Array[],
	output: Uint8Array[],
};

export type MixedVoprfTestVector = VoprfTestVector|BatchVoprfTestVector;

function isBatchVoprfTestVector(vector: MixedVoprfTestVector): vector is BatchVoprfTestVector {
	return Array.isArray(vector.blind);
}

export function runVOPRFTests<T extends Group<T>>(voprf: VOPRF<T>, tests: MixedVoprfTestVector[]) {
	for (const test of tests) {
		const keypair = voprf.deriveKeypair(test.seed, test.keyInfo);
		expect(keypair.secretKey, `${test.name}: 'secretKey' does not match expected`)
			.to.be.equalBytes(test.skS);
		expect(keypair.publicKey, `${test.name}: 'publicKey' does not match expected`)
			.to.be.equalBytes(test.pkS);

		if (isBatchVoprfTestVector(test)) {
			const { blinds, blindedElements } = test.blind.reduce((res: any, _: any, idx: number) => {
				// Client: Blind
				const blindRandomScalar = voprf.suite.decodeScalar(test.blind[idx]);
				const { blind, blindedElement } = voprf.blind(test.input[idx], { blindRandomScalar });
				expect(voprf.suite.encodeScalar(blind), `${test.name}: 'blind' does not match expected`)
					.to.be.equalBytes(test.blind[idx]);
				expect(voprf.suite.encodeElement(blindedElement), `${test.name}: 'blindedElement' does not match expected`)
					.to.be.equalBytes(test.blindedElement[idx]);

				res.blinds.push(blind);
				res.blindedElements.push(blindedElement);
				return res;
			}, { blinds: [], blindedElements: [] });

			// Server: BlindEvaluate
			const proofRandomScalar = voprf.suite.decodeScalar(test.proofRandomScalar);
			const { evaluatedElements, proof } = voprf.blindEvaluateBatch(keypair.secretKey, keypair.publicKey, blindedElements, { proofRandomScalar });
			expect(proof, `${test.name}: 'proof' does not match expected`)
				.to.be.equalBytes(test.proof);
			evaluatedElements.forEach((evaluatedElement, idx) => {
				expect(voprf.suite.encodeElement(evaluatedElement), `${test.name}: 'evaluatedElement' does not match expected`)
					.to.be.equalBytes(test.evaluationElement[idx]);
			});

			test.output.forEach((_: any, idx: number) => {
				// Server: Evaluate (optional)
				const output = voprf.evaluate(keypair.secretKey, test.input[idx]);
				expect(output, `${test.name}: 'evaluate' output does not match expected`)
					.to.be.equalBytes(test.output[idx]);
			});

			// Client: Finalize
			const results = voprf.finalizeBatch(test.input, blinds, evaluatedElements, blindedElements, keypair.publicKey, proof);
			results.forEach((result, idx) => {
				expect(result, `${test.name}: 'finalizeBatch' output does not match expected`)
					.to.be.equalBytes(test.output[idx]);
			});
		} else {
			// Non-batch processing
			// Client: Blind
			const blindRandomScalar = voprf.suite.decodeScalar(test.blind);
			const { blind, blindedElement } = voprf.blind(test.input, { blindRandomScalar });
			expect(voprf.suite.encodeScalar(blind), `${test.name}: 'blind' does not match expected`)
				.to.be.equalBytes(test.blind);
			expect(voprf.suite.encodeElement(blindedElement), `${test.name}: 'blindedElement' does not match expected`)
				.to.be.equalBytes(test.blindedElement);

			// Server: BlindEvaluate
			const proofRandomScalar = voprf.suite.decodeScalar(test.proofRandomScalar);
			const { evaluatedElement, proof } = voprf.blindEvaluate(keypair.secretKey, keypair.publicKey, blindedElement, { proofRandomScalar });
			expect(voprf.suite.encodeElement(evaluatedElement), `${test.name}: 'evaluatedElement' does not match expected`)
				.to.be.equalBytes(test.evaluationElement);
			expect(proof, `${test.name}: 'proof' does not match expected`)
				.to.be.equalBytes(test.proof);

			// Server: Evaluate (optional)
			const output = voprf.evaluate(keypair.secretKey, test.input);
			expect(output, `${test.name}: 'evaluate' output does not match expected`)
				.to.be.equalBytes(test.output);

			// Client: Finalize
			const res = voprf.finalize(test.input, blind, evaluatedElement, blindedElement, keypair.publicKey, proof);
			expect(res, `${test.name}: 'finalize' output does not match expected`)
				.to.be.equalBytes(test.output);
		}
	}
}


export type PoprfTestVector = OprfTestVector & {
	info: Uint8Array,
	pkS: Uint8Array,
	proof: Uint8Array,
	proofRandomScalar: Uint8Array,
};

export type BatchPoprfTestVector = PoprfTestVector & {
	blind: Uint8Array[],
	input: Uint8Array[],
	blindedElement: Uint8Array[],
	evaluationElement: Uint8Array[],
	output: Uint8Array[],
};

export type MixedPoprfTestVector = PoprfTestVector|BatchPoprfTestVector;

function isBatchPoprfTestVector(vector: MixedPoprfTestVector): vector is BatchPoprfTestVector {
	return Array.isArray(vector.blind);
}


export function runPOPRFTests<T extends Group<T>>(poprf: POPRF<T>, tests: MixedPoprfTestVector[]) {
	for (const test of tests) {
		const keypair = poprf.deriveKeypair(test.seed, test.keyInfo);
		expect(keypair.secretKey, `${test.name}: 'secretKey' does not match expected`)
			.to.be.equalBytes(test.skS);
		expect(keypair.publicKey, `${test.name}: 'publicKey' does not match expected`)
			.to.be.equalBytes(test.pkS);

		if (isBatchPoprfTestVector(test)) {
			const { blinds, blindedElements, tweakedKey } = test.blind.reduce((res: any, _: any, idx: number) => {
				// Client: Blind
				const blindRandomScalar = poprf.suite.decodeScalar(test.blind[idx]);
				const { blind, blindedElement, tweakedKey } = poprf.blind(test.input[idx], test.info, keypair.publicKey, { blindRandomScalar });
				expect(poprf.suite.encodeScalar(blind), `${test.name}: 'blind' does not match expected`)
					.to.be.equalBytes(test.blind[idx]);
				expect(poprf.suite.encodeElement(blindedElement), `${test.name}: 'blindedElement' does not match expected`)
					.to.be.equalBytes(test.blindedElement[idx]);

				res.blinds.push(blind);
				res.blindedElements.push(blindedElement);
				res.tweakedKey = tweakedKey;
				return res;
			}, { blinds: [], blindedElements: [], tweakedKey: null });

			// Server: BlindEvaluate
			const proofRandomScalar = poprf.suite.decodeScalar(test.proofRandomScalar);
			const { evaluatedElements, proof } = poprf.blindEvaluateBatch(keypair.secretKey, blindedElements, test.info, { proofRandomScalar });
			expect(proof, `${test.name}: 'proof' does not match expected`)
				.to.be.equalBytes(test.proof);
			evaluatedElements.forEach((evaluatedElement, idx) => {
				expect(poprf.suite.encodeElement(evaluatedElement), `${test.name}: 'evaluatedElement' does not match expected`)
					.to.be.equalBytes(test.evaluationElement[idx]);
			});

			test.output.forEach((_: any, idx: number) => {
				// Server: Evaluate (optional)
				const output = poprf.evaluate(keypair.secretKey, test.input[idx], test.info);
				expect(output, `${test.name}: 'evaluate' output does not match expected`)
					.to.be.equalBytes(test.output[idx]);
			});

			// Client: Finalize
			const results = poprf.finalizeBatch(test.input, blinds, evaluatedElements, blindedElements, proof, test.info, tweakedKey);
			results.forEach((result, idx) => {
				expect(result, `${test.name}: 'finalizeBatch' output does not match expected`)
					.to.be.equalBytes(test.output[idx]);
			});

		} else {
			// Client: Blind
			const blindRandomScalar = poprf.suite.decodeScalar(test.blind);
			const { blind, blindedElement, tweakedKey } = poprf.blind(test.input, test.info, keypair.publicKey, { blindRandomScalar });
			expect(poprf.suite.encodeScalar(blind), `${test.name}: 'blind' does not match expected`)
				.to.be.equalBytes(test.blind);
			expect(poprf.suite.encodeElement(blindedElement), `${test.name}: 'blindedElement' does not match expected`)
				.to.be.equalBytes(test.blindedElement);

			// Server: BlindEvaluate
			const proofRandomScalar = poprf.suite.decodeScalar(test.proofRandomScalar);
			const { evaluatedElement, proof } = poprf.blindEvaluate(keypair.secretKey, blindedElement, test.info, { proofRandomScalar });
			expect(poprf.suite.encodeElement(evaluatedElement), `${test.name}: 'evaluationElement' does not match expected`)
				.to.be.equalBytes(test.evaluationElement);
			expect(proof, `${test.name}: 'proof' does not match expected`)
				.to.be.equalBytes(test.proof);

			// Server: Evaluate (optional)
			const output = poprf.evaluate(keypair.secretKey, test.input, test.info);
			expect(output, `${test.name}: 'evaluate' output does not match expected`)
				.to.be.equalBytes(test.output);

			// Client: Finalize
			const res = poprf.finalize(test.input, blind, evaluatedElement, blindedElement, proof, test.info, tweakedKey);
			expect(res, `${test.name}: 'finalize' output does not match expected`)
				.to.be.equalBytes(test.output);
		}
	}
}
