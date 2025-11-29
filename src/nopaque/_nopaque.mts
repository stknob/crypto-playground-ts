import { abytes, anumber, concatBytes, randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { CHash, equalBytes } from "@noble/curves/utils.js";
import { CurvePoint } from '@noble/curves/abstract/curve.js';

import { hmac } from '@noble/hashes/hmac.js';
import { expand, extract } from '@noble/hashes/hkdf.js';
import { argon2idAsync } from '@noble/hashes/argon2.js';

import { Keypair, type OPRF, type Suite as OprfSuite } from '../oprf/_oprf.mjs';
import { I2OSP } from '../oprf/_utils.mjs';
import { splitByteFields, xorBytes } from './_utils.mjs';

const EMPTY_BUFFER = Uint8Array.of();

const Labels = Object.freeze({
	NOPAQUE_DERIVE_KEYPAIR: utf8ToBytes("NOPAQUE-DeriveKeyPair"),
	NOPAQUE_DERIVE_DH_KEYPAIR: utf8ToBytes("NOPAQUE-DeriveDiffieHellmanKeyPair"),
	CREDENTIAL_RESPONSE_PAD: utf8ToBytes("CredentialResponsePad"),
	MASKING_KEY: utf8ToBytes("MaskingKey"),
	EXPORT_KEY:  utf8ToBytes("ExportKey"),
	AUTH_KEY:    utf8ToBytes("AuthKey"),
	PRIVATE_KEY: utf8ToBytes("PrivateKey"),
	OPRF_KEY:    utf8ToBytes("OprfKey"),
});

/**
 * Nopaque - Opaque without the AKE part
 */

export class NopaqueError extends Error {};
export class EnvelopeRecoveryError extends NopaqueError {};

type SuiteOpts<T extends CurvePoint<any, T>> = {
	oprf: OPRF<T>,
	hash: CHash,    // Hash
	Nh: number,     // Hash output size in bytes
	Npk: number,    // Size of public keys in bytes
	Nsk: number,    // Size of secret keys in bytes
	Nseed: number,  //
	Nn: number,     //
	Nok: number,    // OPRF secret key size
	Noe: number,    // OPRF element size
	Nm: number,     //
	Nx: number,     //
};

export type Suite<T extends CurvePoint<any, T>> = SuiteOpts<T> & {
	encodeScalar: OprfSuite<T>["encodeScalar"],
	decodeScalar: OprfSuite<T>["decodeScalar"],
	encodeElement: OprfSuite<T>["encodeElement"],
	decodeElement: OprfSuite<T>["decodeElement"],
};

export function createSuite<T extends CurvePoint<any, T>>(opts: SuiteOpts<T>): Readonly<Suite<T>> {
	const { suite: oprfSuite } = opts.oprf;
	return Object.freeze({
		...opts,
		encodeScalar: (scalar) => oprfSuite.encodeScalar(scalar),
		decodeScalar: (bytes) => oprfSuite.decodeScalar(bytes),
		encodeElement: (element) => oprfSuite.encodeElement(element),
		decodeElement: (bytes) => oprfSuite.decodeElement(bytes),
	});
}

interface ServerConfig<T extends CurvePoint<any, T>> {
	suite: Suite<T>,
	customDeriveKeyPairLabel?: Uint8Array,
}

interface ClientConfig<T extends CurvePoint<any, T>> {
	suite: Suite<T>,
	stretch(msg: Uint8Array): Promise<Uint8Array>,
	customDeriveDhKeyPairLabel?: Uint8Array,
}
export interface ClientState {
	password?: Uint8Array,
	blind?: Uint8Array,
}


interface CleartextCredentials {
	serverPublicKey: Uint8Array,
	serverIdentity: Uint8Array,
	clientIdentity: Uint8Array,
}

/**
*
* @param serverPublicKey
* @param clientPublicKey
* @param serverIdentity
* @param clientIdentity
*/
function createCleartextCredentials(serverPublicKey: Uint8Array, clientPublicKey: Uint8Array, serverIdentity: Uint8Array, clientIdentity: Uint8Array): CleartextCredentials {
	return {
		serverPublicKey,
		clientIdentity: clientIdentity ?? clientPublicKey,
		serverIdentity: serverIdentity ?? serverPublicKey,
	};
}

/**
 * struct Envelope {
 *    envelopeNonce uint8[Nn]
 *    authTag uint8[Nm]
 * }
 */
type Envelope = Uint8Array;

interface StoreOptions {
	envelopeNonce?: Uint8Array,
	customDeriveDhKeyPairLabel?: Uint8Array,
}

interface StoreResult {
	envelope: Envelope,
	clientPublicKey: Uint8Array,
	maskingKey: Uint8Array,
	exportKey: Uint8Array,
}

/**
 * 4.1.2. Envelope Creation
 * Client:
 */
function store<T extends CurvePoint<any, T>>(suite: Suite<T>, randomizedPassword: Uint8Array, serverPublicKey: Uint8Array, serverIdentity?: Uint8Array, clientIdentity?: Uint8Array, options?: StoreOptions): StoreResult {
	const envelopeNonce = options?.envelopeNonce ?? randomBytes(suite.Nn);
	const maskingKey = expand(suite.hash, randomizedPassword, Labels.MASKING_KEY, suite.Nh);
	const exportKey  = expand(suite.hash, randomizedPassword, concatBytes(envelopeNonce, Labels.EXPORT_KEY), suite.Nh);
	const authKey  = expand(suite.hash, randomizedPassword, concatBytes(envelopeNonce, Labels.AUTH_KEY), suite.Nh);
	const seed  = expand(suite.hash, randomizedPassword, concatBytes(envelopeNonce, Labels.PRIVATE_KEY), suite.Nseed);

	const { publicKey: clientPublicKey } = suite.oprf.deriveKeypair(seed, options?.customDeriveDhKeyPairLabel ?? Labels.NOPAQUE_DERIVE_DH_KEYPAIR);
	const cleartextCredentials = createCleartextCredentials(serverPublicKey, clientPublicKey, serverIdentity, clientIdentity);

	const authTag = hmac(suite.hash, authKey, concatBytes(
		envelopeNonce,
		serverPublicKey,
		I2OSP(cleartextCredentials.serverIdentity.length, 2),
		cleartextCredentials.serverIdentity,
		I2OSP(cleartextCredentials.clientIdentity.length, 2),
		cleartextCredentials.clientIdentity,
	));

	return {
		envelope: concatBytes(
			envelopeNonce,
			authTag,
		),
		clientPublicKey,
		maskingKey,
		exportKey,
	};
}

interface RecoverOptions {
	customDeriveDhKeyPairLabel?: Uint8Array,
}

interface RecoverResult {
	clientSecretKey: Uint8Array,
	cleartextCredentials: CleartextCredentials,
	exportKey: Uint8Array,
}

/**
 * Client:
 */
function recover<T extends CurvePoint<any, T>>(suite: Suite<T>, randomizedPassword: Uint8Array, serverPublicKey: Uint8Array, envelope: Envelope, serverIdentity: Uint8Array, clientIdentity: Uint8Array, options?: RecoverOptions): RecoverResult {
	const [ envelopeNonce, envelopeAuthTag ]  = splitByteFields(envelope, [ suite.Nn, suite.Nm ]);
	const exportKey = expand(suite.hash, randomizedPassword, concatBytes(envelopeNonce, Labels.EXPORT_KEY), suite.Nh);
	const authKey = expand(suite.hash, randomizedPassword, concatBytes(envelopeNonce, Labels.AUTH_KEY), suite.Nh);
	const seed = expand(suite.hash, randomizedPassword, concatBytes(envelopeNonce, Labels.PRIVATE_KEY), suite.Nseed);

	const { secretKey: clientSecretKey, publicKey: clientPublicKey } = suite.oprf.deriveKeypair(seed, options?.customDeriveDhKeyPairLabel ?? Labels.NOPAQUE_DERIVE_DH_KEYPAIR);
	const cleartextCredentials = createCleartextCredentials(serverPublicKey, clientPublicKey, serverIdentity, clientIdentity);

	const authTag = hmac(suite.hash, authKey, concatBytes(
		envelopeNonce,
		serverPublicKey,
		I2OSP(cleartextCredentials.serverIdentity.length, 2),
		cleartextCredentials.serverIdentity,
		I2OSP(cleartextCredentials.clientIdentity.length, 2),
		cleartextCredentials.clientIdentity,
	));

	// Compare expected vs. server-provided auth tag
	if (!equalBytes(authTag, envelopeAuthTag))
		throw new EnvelopeRecoveryError();

	return {
		clientSecretKey,
		cleartextCredentials,
		exportKey,
	};
}

/**
 * Client: Registration request
 * struct RegistrationRequest {
 *   blindedMessage uint8[Noe]
 * }
 */
type RegistrationRequest = Uint8Array;

interface CreateRegistrationOptions {
	blind: Uint8Array,  // Only for unit tests
}

interface CreateRegistrationRequestResult {
	request: RegistrationRequest,
	blind: Uint8Array,
}


/**
 * Server: Registration response
 *
 * struct RegistrationResponse {
 *   evaluatedMessage uint8[Noe]
 *   serverPublicKey uint8[Npk]
 * }
 */
type RegistrationResponse = Uint8Array;

/**
 * Client: Finalize registration
 *
 * struct RegistrationRecord {
 *   clientPublicKey uint8[Npk]
 *   maskingKey uint8[Nh]
 *   envelope: Envelope
 * }
 */
type RegistrationRecord = Uint8Array;

interface FinalizeRegistrationOptions {
	envelopeNonce?: Uint8Array,
}

interface FinalizeRegistrationRequestResult {
	record: RegistrationRecord,
	exportKey: Uint8Array,
}

/**
 * Client: Recover request
 *
 * struct RecoverRequest {
 *   blindedMessage uint8[Noe]
 * }
 */
type RecoverRequest = Uint8Array;

/**
 * Server: Recover response
 */
type RecoverResponse = Uint8Array;

interface CreateRecoverRequestOptions {
	blind?: Uint8Array,
}

interface CreateRecoverResponseOptions {
	maskingNonce?: Uint8Array,
}

const EMPTY_SALT = new Uint8Array(16);
function defaultStretch<T extends CurvePoint<any, T>>(suite: Suite<T>, msg: Uint8Array): Promise<Uint8Array> {
	anumber(suite.Nh); abytes(msg);
	return argon2idAsync(msg, EMPTY_SALT, { dkLen: suite.Nh, p: 4, m: 2048, t: 1 });
}


export type ServerOpts = {
	customDeriveKeyPairLabel?: Uint8Array,
};

export type ClientOpts = {
	stretch?(msg: Uint8Array): Promise<Uint8Array>,
	customDeriveDhKeyPairLabel?: Uint8Array,
};


export type Client<T extends CurvePoint<any, T>> = ClientOpts & {
	randomSecret(): Uint8Array,
	createRegistrationRequest(password: Uint8Array, options?: CreateRegistrationOptions): CreateRegistrationRequestResult,
	finalizeRegistrationRequest(password: Uint8Array, blind: Uint8Array, response: RegistrationResponse, serverIdentity?: Uint8Array, clientIdentity?: Uint8Array, options?: FinalizeRegistrationOptions): Promise<FinalizeRegistrationRequestResult>,
	createRecoverRequest(state: ClientState, password: Uint8Array, options?: CreateRecoverRequestOptions): RecoverRequest,
	finalizeRecoverRequest(state: ClientState, ke2: RecoverResponse, serverIdentity?: Uint8Array, clientIdentity?: Uint8Array): Promise<Uint8Array>,
};

export function createClient<T extends CurvePoint<any, T>>(suite: Suite<T>, opts: ClientOpts): Client<T> {
	const config = { suite, stretch: (msg) => defaultStretch(suite, msg), ...(opts ?? {}) } as ClientConfig<T>;
	return Object.freeze({
		...opts,
		randomSecret: () => randomBytes(suite.Nseed),
		createRegistrationRequest(password, options) {
			const { blind, blindedElement } = suite.oprf.blind(password, { blindRandomScalar: options?.blind && suite.oprf.decodeScalar(options.blind) });
			const blindedMessage = suite.encodeElement(blindedElement);

			return {
				blind: suite.encodeScalar(blind),
				request: blindedMessage,
			};
		},
		async finalizeRegistrationRequest(password, blind, response, serverIdentity, clientIdentity, options) {
			const [ evaluatedMessage, serverPublicKey ] = splitByteFields(response, [ suite.Noe, suite.Npk ]);
			const evaluatedElement = suite.decodeElement(evaluatedMessage);
			const oprfOutput = suite.oprf.finalize(password, suite.decodeScalar(blind), evaluatedElement);

			const stretchedOprfOutput = await config.stretch(oprfOutput);
			const randomizedPassword = extract(suite.hash, concatBytes(oprfOutput, stretchedOprfOutput), EMPTY_BUFFER);
			const { envelope, clientPublicKey, maskingKey, exportKey } = store(suite, randomizedPassword, serverPublicKey, serverIdentity, clientIdentity,
				{ ...options as StoreOptions, customDeriveDhKeyPairLabel: opts?.customDeriveDhKeyPairLabel });

			return {
				record: concatBytes(clientPublicKey, maskingKey, envelope),
				exportKey,
			};
		},
		createRecoverRequest(state, password, options) {
			const { blind, blindedElement } = suite.oprf.blind(password, { blindRandomScalar: options?.blind && suite.decodeScalar(options.blind) });
			const blindedMessage = suite.encodeElement(blindedElement);
			state.password = password;
			state.blind = suite.encodeScalar(blind);
			return blindedMessage;
		},
		async finalizeRecoverRequest(state, ke2, serverIdentity, clientIdentity) {
			const { decodeScalar, decodeElement, oprf, hash, Nh, Nn, Npk, Nm, Noe } = config.suite;
			const [ evaluatedMessage, maskingNonce, maskedResponse ] = splitByteFields(ke2, [
				Noe,			// evaluatedMessage[Noe]
				Nn,				// maskingNonce[Nn]
				Npk + Nn + Nm,	// maskedResponse[Npk + Nn + Nm]
			]);
			const evaluatedElement = decodeElement(evaluatedMessage);
			const oprfOutput = oprf.finalize(state.password, decodeScalar(state.blind), evaluatedElement);
			const stretchedOprfOutput = await config.stretch(oprfOutput);
			const randomizedPassword = extract(hash, concatBytes(oprfOutput, stretchedOprfOutput), EMPTY_BUFFER);

			const maskingKey = expand(hash, randomizedPassword, Labels.MASKING_KEY, Nh);
			const credentialResponsePad = expand(hash, maskingKey, concatBytes(maskingNonce, Labels.CREDENTIAL_RESPONSE_PAD), Npk + Nn + Nm);

			const unmaskedResponse = xorBytes(credentialResponsePad, maskedResponse);
			const [ serverPublicKey, envelopeNonce, authTag ] = splitByteFields(unmaskedResponse, [ Npk, Nn, Nm ]);

			const { exportKey } = recover(config.suite, randomizedPassword, serverPublicKey, concatBytes(envelopeNonce, authTag), serverIdentity, clientIdentity,
				{ customDeriveDhKeyPairLabel: opts?.customDeriveDhKeyPairLabel });
			return exportKey;
		},
	});
}



export type Server<T extends CurvePoint<any, T>> = ServerOpts & {
	randomSeed(): Uint8Array,
	randomKeypair(): Keypair,
	createRegistrationResponse(request: RegistrationRequest, serverPublicKey: Uint8Array, credentialIdentifier: Uint8Array, oprfSeed: Uint8Array): RegistrationResponse,
	createRecoverResponse(serverKeypair: Keypair, record: RegistrationRecord, credentialIdentifier: Uint8Array, oprfSeed: Uint8Array, ke1: RecoverRequest, options?: CreateRecoverResponseOptions): RecoverResponse,
};

export function createServer<T extends CurvePoint<any, T>>(suite: Suite<T>, opts: ServerOpts): Server<T> {
	const config = { suite, ...(opts ?? {}) } as ServerConfig<T>;
	return Object.freeze({
		...opts,
		randomSeed: () => randomBytes(config.suite.Nseed),
		randomKeypair: () => config.suite.oprf.randomKeypair(),
		createRegistrationResponse(request, serverPublicKey, credentialIdentifier, oprfSeed) {
			const seed = expand(suite.hash, oprfSeed, concatBytes(credentialIdentifier, Labels.OPRF_KEY), suite.Nok);
			const { secretKey: oprfKey } = suite.oprf.deriveKeypair(seed, opts?.customDeriveKeyPairLabel ?? Labels.NOPAQUE_DERIVE_KEYPAIR);

			const blindedElement = suite.decodeElement(request);
			const evaluatedElement = suite.oprf.blindEvaluate(oprfKey, blindedElement);
			const evaluatedMessage = suite.encodeElement(evaluatedElement);

			return concatBytes(
				evaluatedMessage,
				serverPublicKey,
			);
		},
		createRecoverResponse(serverKeypair, record, credentialIdentifier, oprfSeed, ke1, options) {
			const [ blindedMessage ] = splitByteFields(ke1, [
				suite.Noe,	// credentialRequest.blindedMesssage
			]);
			const seed = expand(suite.hash, oprfSeed, concatBytes(credentialIdentifier, Labels.OPRF_KEY), suite.Nok);
			const { secretKey: oprfKey } = suite.oprf.deriveKeypair(seed, opts?.customDeriveKeyPairLabel ?? Labels.NOPAQUE_DERIVE_KEYPAIR);
			const blindedElement = suite.decodeElement(blindedMessage);
			const evaluatedElement = suite.oprf.blindEvaluate(oprfKey, blindedElement);
			const evaluatedMessage = suite.encodeElement(evaluatedElement);

			const [ _clientPublicKey, maskingKey, envelopeNonce, envelopeAuthTag ] = splitByteFields(record, [
				suite.Npk,	// clientPublicKey
				suite.Nh,	// maskingKey
				suite.Nn,	// envelope.envelopeNonce
				suite.Nm,	// envelope.authTag
			]);

			const maskingNonce = options?.maskingNonce ?? randomBytes(suite.Nn);
			const credentialResponsePad = expand(suite.hash, maskingKey, concatBytes(maskingNonce, Labels.CREDENTIAL_RESPONSE_PAD), suite.Npk + suite.Nn + suite.Nm);
			const unmaskedResponse = concatBytes(serverKeypair.publicKey, envelopeNonce, envelopeAuthTag);
			const maskedResponse = xorBytes(credentialResponsePad, unmaskedResponse);

			return concatBytes(
				evaluatedMessage,
				maskingNonce,
				maskedResponse,
			);
		},
	});
}
