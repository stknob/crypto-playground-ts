import { abytes, anumber, concatBytes, randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { CHash, equalBytes } from "@noble/curves/utils.js";
import { CurvePoint } from '@noble/curves/abstract/curve.js';

import { hmac } from '@noble/hashes/hmac.js';
import { expand, extract } from '@noble/hashes/hkdf.js';
import { argon2idAsync } from "@noble/hashes/argon2.js";

import { Keypair, type OPRF, type Suite as OprfSuite } from '../oprf/_oprf.mjs';
import { I2OSP } from '../oprf/_utils.mjs';
import { xorBytes } from './_utils.mjs';
import { splitByteFields } from "../nopaque/_utils.mjs";

const EMPTY_BUFFER = Uint8Array.of();

const Labels = Object.freeze({
	OPAQUE_PREFIX: utf8ToBytes("OPAQUE-"),
	OPAQUE_V1_PREFIX:   utf8ToBytes("OPAQUEv1-"),
	OPAQUE_DERIVE_KEYPAIR: utf8ToBytes("OPAQUE-DeriveKeyPair"),
	OPAQUE_DERIVE_DH_KEYPAIR: utf8ToBytes("OPAQUE-DeriveDiffieHellmanKeyPair"),
	MASKING_KEY: utf8ToBytes("MaskingKey"),
	EXPORT_KEY:  utf8ToBytes("ExportKey"),
	AUTH_KEY:    utf8ToBytes("AuthKey"),
	PRIVATE_KEY: utf8ToBytes("PrivateKey"),
	OPRF_KEY:    utf8ToBytes("OprfKey"),
	CREDENTIAL_RESPONSE_PAD: utf8ToBytes("CredentialResponsePad"),
	HANDSHAKE_SECRET: utf8ToBytes("HandshakeSecret"),
	SESSION_KEY: utf8ToBytes("SessionKey"),
	SERVER_MAC: utf8ToBytes("ServerMAC"),
	CLIENT_MAC: utf8ToBytes("ClientMAC"),
});

export class OpaqueError extends Error {};
export class EnvelopeRecoveryError extends OpaqueError {};
export class ServerAuthenticationError extends OpaqueError {};
export class ClientAuthenticationError extends OpaqueError {};


type SuiteOpts<T extends CurvePoint<any, T>> = {
	oprf: OPRF<T>,
	hash: CHash,    // Hash
	Nh: number,     // Hash output size in bytes
	Npk: number,    // Size of public keys in bytes
	Nsk: number,    // Size of secret keys in bytes
	Nseed: number,  //
	Nn: number,     //
	Nok: number,    // OPRF secret key size
	Noe: number,	// OPRF element size
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
	context?: Uint8Array,
}

interface ClientConfig<T extends CurvePoint<any, T>> extends ServerConfig<T> {
	stretch(msg: Uint8Array): Promise<Uint8Array>,
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
function createCleartextCredentials(serverPublicKey: Uint8Array, clientPublicKey: Uint8Array, serverIdentity?: Uint8Array, clientIdentity?: Uint8Array): CleartextCredentials {
	return {
		serverPublicKey,
		clientIdentity: clientIdentity ?? clientPublicKey,
		serverIdentity: serverIdentity ?? serverPublicKey,
	};
}

type Envelope = Uint8Array;

interface StoreOptions {
	envelopeNonce?: Uint8Array,
};

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
	const envelopeNonce = options?.envelopeNonce ?? randomBytes(suite.Nn); // Nn = 32 (?)
	const maskingKey = expand(suite.hash, randomizedPassword, Labels.MASKING_KEY, suite.Nh);	// "Nh"?
	const exportKey  = expand(suite.hash, randomizedPassword, concatBytes(envelopeNonce, Labels.EXPORT_KEY), suite.Nh);		// "Nh"?
	const authKey  = expand(suite.hash, randomizedPassword, concatBytes(envelopeNonce, Labels.AUTH_KEY), suite.Nh);			// "Nh"?
	const seed  = expand(suite.hash, randomizedPassword, concatBytes(envelopeNonce, Labels.PRIVATE_KEY), suite.Nseed);		// "Nseed"?

	const { publicKey: clientPublicKey } = suite.oprf.deriveKeypair(seed, Labels.OPAQUE_DERIVE_DH_KEYPAIR);
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
		envelope: concatBytes(envelopeNonce, authTag),
		clientPublicKey,
		maskingKey,
		exportKey,
	};
}

interface RecoverResult {
	clientSecretKey: Uint8Array,
	cleartextCredentials: CleartextCredentials,
	exportKey: Uint8Array,
}

/**
 * Client:
 */
function recover<T extends CurvePoint<any, T>>(suite: Suite<T>, randomizedPassword: Uint8Array, serverPublicKey: Uint8Array, envelope: Envelope, serverIdentity: Uint8Array, clientIdentity: Uint8Array): RecoverResult {
	const [ envelopeNonce, envelopeAuthTag ] = splitByteFields(envelope, [ suite.Nn, suite.Nm ]);
	const exportKey  = expand(suite.hash, randomizedPassword, concatBytes(envelopeNonce, Labels.EXPORT_KEY), suite.Nh);	// "Nh"?
	const authKey  = expand(suite.hash, randomizedPassword, concatBytes(envelopeNonce, Labels.AUTH_KEY), suite.Nh);		// "Nh"?
	const seed  = expand(suite.hash, randomizedPassword, concatBytes(envelopeNonce, Labels.PRIVATE_KEY), suite.Nseed);		// "Nseed"?

	const { secretKey: clientSecretKey, publicKey: clientPublicKey } = suite.oprf.deriveKeypair(seed, Labels.OPAQUE_DERIVE_DH_KEYPAIR);
	const cleartextCredentials = createCleartextCredentials(serverPublicKey, clientPublicKey, serverIdentity, clientIdentity);

	const expectedTag = hmac(suite.hash, authKey, concatBytes(
		envelopeNonce,
		serverPublicKey,
		I2OSP(cleartextCredentials.serverIdentity.length, 2),
		cleartextCredentials.serverIdentity,
		I2OSP(cleartextCredentials.clientIdentity.length, 2),
		cleartextCredentials.clientIdentity,
	));

	//
	if (!equalBytes(expectedTag, envelopeAuthTag))
		throw new EnvelopeRecoveryError();

	return {
		clientSecretKey,
		cleartextCredentials,
		exportKey,
	};
}

type RegistrationRequest = Uint8Array;

interface CreateRegistrationOptions {
	blind: Uint8Array,  // Only for unit tests
}

interface CreateRegistrationRequestResult {
	request: RegistrationRequest,
	blind: Uint8Array,
}

/**
 * Client:
 */
function createRegistrationRequest<T extends CurvePoint<any, T>>(config: ClientConfig<T>, password: Uint8Array, options?: CreateRegistrationOptions): CreateRegistrationRequestResult {
	const { suite } = config;
	const { blind, blindedElement } = suite.oprf.blind(password, { blindRandomScalar: options?.blind && suite.oprf.decodeScalar(options.blind) });
	const blindedMessage = suite.encodeElement(blindedElement);

	return {
		blind: suite.encodeScalar(blind),
		request: blindedMessage,
	};
}


type RegistrationResponse = Uint8Array;


/**
 * Server: Process client's registration request
 * @param request
 * @param serverPublicKey Encoded Ristretto255 public key
 * @param credentialIdentifier ??
 * @param oprfSeed Nh bytes of seed to generate oprf key
 */
function createRegistrationResponse<T extends CurvePoint<any, T>>(config: ServerConfig<T>, request: RegistrationRequest, serverPublicKey: Uint8Array, credentialIdentifier: Uint8Array, oprfSeed: Uint8Array): RegistrationResponse {
	const { suite } = config;
	const seed = expand(suite.hash, oprfSeed, concatBytes(credentialIdentifier, Labels.OPRF_KEY), suite.Nok);	// Nok??
	const { secretKey: oprfKey } = suite.oprf.deriveKeypair(seed, Labels.OPAQUE_DERIVE_KEYPAIR);

	const blindedElement = suite.decodeElement(request);
	const evaluatedElement = suite.oprf.blindEvaluate(oprfKey, blindedElement);
	const evaluatedMessage = suite.encodeElement(evaluatedElement);

	return concatBytes(
		evaluatedMessage,
		serverPublicKey,
	);
}

type RegistrationRecord = Uint8Array;

interface FinalizeRegistrationOptions {
	envelopeNonce?: Uint8Array,
}

interface FinalizeRegistrationResult {
	record: RegistrationRecord,
	exportKey: Uint8Array,
}

/**
 * Client: Generate record
 */
async function finalizeRegistrationRequest<T extends CurvePoint<any, T>>(config: ClientConfig<T>, password: Uint8Array, blind: Uint8Array, response: RegistrationResponse, serverIdentity?: Uint8Array, clientIdentity?: Uint8Array, options?: FinalizeRegistrationOptions): Promise<FinalizeRegistrationResult> {
	const { suite } = config;
	const [ evaluatedMessage, serverPublicKey ] = splitByteFields(response, [ suite.Noe, suite.Npk ]);
	const evaluatedElement = suite.decodeElement(evaluatedMessage);
	const oprfOutput = suite.oprf.finalize(password, suite.decodeScalar(blind), evaluatedElement);

	const stretchedOprfOutput = await config.stretch(oprfOutput);
	const randomizedPassword = extract(suite.hash, concatBytes(oprfOutput, stretchedOprfOutput), EMPTY_BUFFER);
	const { envelope, clientPublicKey, maskingKey, exportKey } = store(suite, randomizedPassword, serverPublicKey, serverIdentity, clientIdentity, options as StoreOptions);

	return {
		exportKey,
		record: concatBytes(
			clientPublicKey,
			maskingKey,
			envelope,
		),
	};
}


type CredentialRequest = Uint8Array;
type CredentialResponse = Uint8Array;

interface CreateCredentialRequestOptions {
	blind?: Uint8Array,
}

interface CreateCredentialRequestResult {
	request: CredentialRequest,
	blind: Uint8Array,
}

function createCredentialRequest<T extends CurvePoint<any, T>>(config: ClientConfig<T>, password: Uint8Array, options?: CreateCredentialRequestOptions): CreateCredentialRequestResult {
	const { suite } = config;
	const { blind, blindedElement } = suite.oprf.blind(password, { blindRandomScalar: options?.blind && suite.decodeScalar(options.blind) });
	const blindedMessage = suite.encodeElement(blindedElement);

	return {
		blind: suite.encodeScalar(blind),
		request: blindedMessage,
	};
}

interface CreateCredentialOptions {
	maskingNonce?: Uint8Array,
}

function createCredentialResponse<T extends CurvePoint<any, T>>(config: ServerConfig<T>, request: CredentialRequest, serverPublicKey: Uint8Array, record: RegistrationRecord, credentialIdentifier: Uint8Array, oprfSeed: Uint8Array, options?: CreateCredentialOptions): CredentialResponse {
	const { suite } = config;
	const seed = expand(suite.hash, oprfSeed, concatBytes(credentialIdentifier, Labels.OPRF_KEY), suite.Nok);	// Nok
	const { secretKey: oprfKey } = suite.oprf.deriveKeypair(seed, Labels.OPAQUE_DERIVE_KEYPAIR);
	const [ blindedMessage ] = splitByteFields(request, [ suite.Noe ]);
	const blindedElement = suite.decodeElement(blindedMessage);
	const evaluatedElement = suite.oprf.blindEvaluate(oprfKey, blindedElement);
	const evaluatedMessage = suite.encodeElement(evaluatedElement);

	const [ _clientPublicKey, maskingKey, envelopeNonce, envelopeAuthTag ] = splitByteFields(record, [
		suite.Npk,
		suite.Nh,
		suite.Nn,
		suite.Nm,
	]);

	const maskingNonce = options?.maskingNonce ?? randomBytes(suite.Nn);	// Nn
	const credentialResponsePad = expand(suite.hash, maskingKey, concatBytes(maskingNonce, Labels.CREDENTIAL_RESPONSE_PAD), suite.Npk + suite.Nn + suite.Nm);	// Npk + Nn + Nm
	const unmaskedResponse = concatBytes(serverPublicKey, envelopeNonce, envelopeAuthTag);	// Meh... serialize envelope
	const maskedResponse = xorBytes(credentialResponsePad, unmaskedResponse);

	return concatBytes(
		evaluatedMessage,
		maskingNonce,
		maskedResponse,
	);
}

interface RecoverCredentialsResult {
	cleartextCredentials: CleartextCredentials,
	clientSecretKey: Uint8Array,
	exportKey: Uint8Array,
}

// 6.3.2.3. RecoverCredentials
async function recoverCredentials<T extends CurvePoint<any, T>>(config: ClientConfig<T>, password: Uint8Array, blind: Uint8Array, response: CredentialResponse, serverIdentity: Uint8Array, clientIdentity: Uint8Array): Promise<RecoverCredentialsResult> {
	const { decodeScalar, decodeElement, oprf, hash, Nh, Nn, Npk, Nm, Noe } = config.suite;
	const [ evaluatedMessage, maskingNonce, maskedResponse ] = splitByteFields(response, [ Noe, Nn, Npk + Nn + Nm ]);
	const evaluatedElement = decodeElement(evaluatedMessage);
	const oprfOutput = oprf.finalize(password, decodeScalar(blind), evaluatedElement);
	const stretchedOprfOutput = await config.stretch(oprfOutput);
	const randomizedPassword = extract(hash, concatBytes(oprfOutput, stretchedOprfOutput), EMPTY_BUFFER);

	const maskingKey = expand(hash, randomizedPassword, Labels.MASKING_KEY, Nh);	// Nh
	const credentialResponseLength = Npk + Nn + Nm;	// Npk + Nn + Nm
	const credentialResponsePad = expand(hash, maskingKey, concatBytes(maskingNonce, Labels.CREDENTIAL_RESPONSE_PAD), credentialResponseLength);

	const unmaskedResponse = xorBytes(credentialResponsePad, maskedResponse);	// Meh... deserialize envelope
	const [ serverPublicKey, envelopeNonce, authTag ] = splitByteFields(unmaskedResponse, [ Npk, Nn, Nm ]);

	const { clientSecretKey, cleartextCredentials, exportKey } = recover(config.suite, randomizedPassword, serverPublicKey, concatBytes(envelopeNonce, authTag), serverIdentity, clientIdentity);

	return {
		cleartextCredentials,
		clientSecretKey,
		exportKey,
	};
}



// 6.4.2.1. Transcript Functions - Expand-Label
function expandLabel<T extends CurvePoint<any, T>>(suite: Suite<T>, secret: Uint8Array, label: Uint8Array, context: Uint8Array, length: number): Uint8Array {
	const labelSize = Labels.OPAQUE_PREFIX.length + (label?.length ?? 0);
	return expand(suite.hash, secret, concatBytes(
		I2OSP(length, 2),
		I2OSP(labelSize, 1), Labels.OPAQUE_PREFIX, label,
		I2OSP(context.length, 1), context), length);
}

// 6.4.2.1. Transcript Functions - Derive-Secret
function deriveSecret<T extends CurvePoint<any, T>>(suite: Suite<T>, secret: Uint8Array, label: Uint8Array, context: Uint8Array): Uint8Array {
	return expandLabel(suite, secret, label, context, suite.Nx);
}

// 6.4.2.2. Shared Secret Derivation - DeriveKeys
function deriveKeys<T extends CurvePoint<any, T>>(suite: Suite<T>, ikm: Uint8Array, preamble: Uint8Array) {
	const prk = extract(suite.hash, ikm, EMPTY_BUFFER);
	const hashedPreamble = suite.hash(preamble);
	const handshakeSecret = deriveSecret(suite, prk, Labels.HANDSHAKE_SECRET, hashedPreamble);
	const sessionKey = deriveSecret(suite, prk, Labels.SESSION_KEY, hashedPreamble);

	const km2 = deriveSecret(suite, handshakeSecret, Labels.SERVER_MAC, EMPTY_BUFFER);
	const km3 = deriveSecret(suite, handshakeSecret, Labels.CLIENT_MAC, EMPTY_BUFFER);

	return {
		sessionKey,
		km2, km3,
	};
}

type AuthRequest = Uint8Array;
type AuthResponse = Uint8Array;

type KE1 = Uint8Array;
type KE2 = Uint8Array;
type KE3 = Uint8Array;

//
function buildPreamble(clientIdentity: Uint8Array, ke1: KE1, serverIdentity: Uint8Array, credentialResponse: CredentialResponse, serverNonce: Uint8Array, serverPublicKeyshare: Uint8Array, context: Uint8Array): Uint8Array {
	return concatBytes(
		Labels.OPAQUE_V1_PREFIX,
		I2OSP(context.length, 2), context,
		I2OSP(clientIdentity.length, 2), clientIdentity,
		ke1,
		I2OSP(serverIdentity.length, 2), serverIdentity,
		credentialResponse,
		serverNonce,
		serverPublicKeyshare,
	);
}

interface AuthClientStartOptions {
	clientKeyshareSeed?: Uint8Array,
	clientNonce?: Uint8Array,
}

/**
 *
 * @param state
 * @param request
 * @returns
 */
function authClientStart<T extends CurvePoint<any, T>>(config: ClientConfig<T>, state: ClientState, request: CredentialRequest, options?: AuthClientStartOptions): KE1 {
	const { suite } = config;
	const clientNonce = options?.clientNonce ?? randomBytes(suite.Nn);	// Nn
	const clientKeyshareSeed = options?.clientKeyshareSeed ?? randomBytes(suite.Nseed);	// Nseed
	const { secretKey: clientSecret, publicKey: clientPublicKeyshare } = suite.oprf.deriveKeypair(clientKeyshareSeed, Labels.OPAQUE_DERIVE_DH_KEYPAIR);

	const ke1 = concatBytes(
		request,
		clientNonce,
		clientPublicKeyshare,
	);

	state.clientSecret = clientSecret;
	state.ke1 = ke1;
	return ke1;
}

interface AuthServerRespondOptions {
	serverKeyshareSeed?: Uint8Array,
	serverNonce?: Uint8Array,
}

// 6.4.4. 3DH Server Functions
function authServerRespond<T extends CurvePoint<any, T>>(config: ServerConfig<T>, state: ServerState, cleartextCredentials: CleartextCredentials, serverPrivateKey: Uint8Array, clientPublicKey: Uint8Array, ke1: KE1,
	credentialResponse: CredentialResponse, options?: AuthServerRespondOptions): AuthResponse
{
	const { context, suite } = config;
	const serverNonce = options?.serverNonce ?? randomBytes(suite.Nn);
	const serverKeyshareSeed = options?.serverKeyshareSeed ?? randomBytes(suite.Nseed);
	const { secretKey: serverPrivateKeyshare, publicKey: serverPublicKeyshare } = suite.oprf.deriveKeypair(serverKeyshareSeed, Labels.OPAQUE_DERIVE_DH_KEYPAIR);

	const preamble = buildPreamble(
		cleartextCredentials.clientIdentity,
		ke1,
		cleartextCredentials.serverIdentity,
		credentialResponse,
		serverNonce,
		serverPublicKeyshare,
		context ?? EMPTY_BUFFER,	// Optional, but recommended
	);

	const serverPrivateKeyshareScalar = suite.decodeScalar(serverPrivateKeyshare);
	const serverPrivateScalar = suite.decodeScalar(serverPrivateKey);

	const [ _blindedMessage, _clientNonce, clientPublicKeyshare ] = splitByteFields(ke1, [ suite.Noe, suite.Nn, suite.Npk ]);
	const clientPublicKeyshareElement = suite.decodeElement(clientPublicKeyshare);
	const clientPublicKeyElement = suite.decodeElement(clientPublicKey);

	const dh1 = clientPublicKeyshareElement.multiply(serverPrivateKeyshareScalar);
	const dh2 = clientPublicKeyshareElement.multiply(serverPrivateScalar);
	const dh3 = clientPublicKeyElement.multiply(serverPrivateKeyshareScalar);

	const ikm = concatBytes(
		suite.encodeElement(dh1),
		suite.encodeElement(dh2),
		suite.encodeElement(dh3),
	);

	const { km2, km3, sessionKey } = deriveKeys(suite, ikm, preamble);
	const serverMac = hmac(suite.hash, km2, suite.hash(preamble));

	state.sessionKey = sessionKey;
	state.expectedClientMac = hmac(suite.hash, km3, suite.hash(concatBytes(
		preamble, serverMac,
	)));

	return concatBytes(
		serverNonce,
		serverPublicKeyshare,
		serverMac,
	);
}

interface AuthClientFinalizeResult {
	sessionKey: Uint8Array,
	ke3: KE3,
}

function authClientFinalize<T extends CurvePoint<any, T>>(config: ClientConfig<T>, state: ClientState, cleartextCredentials: CleartextCredentials, clientSecretKey: Uint8Array, ke2: KE2): AuthClientFinalizeResult {
	const { context, suite } = config;
	const clientSecretScalar = suite.decodeScalar(state.clientSecret);
	const clientPrivateScalar = suite.decodeScalar(clientSecretKey);

	const [ credentialResponse, serverNonce, serverPublicKeyshare, serverMac ] = splitByteFields(ke2, [
		suite.Noe + suite.Nn + suite.Npk + suite.Nn + suite.Nm,	// CredentialResponse
		suite.Nn,
		suite.Npk,
		suite.Nm,
	]);
	const serverPublicKeyshareElement = suite.decodeElement(serverPublicKeyshare);
	const serverPublicKeyElement = suite.decodeElement(cleartextCredentials.serverPublicKey);

	const dh1 = serverPublicKeyshareElement.multiply(clientSecretScalar);
	const dh2 = serverPublicKeyElement.multiply(clientSecretScalar);
	const dh3 = serverPublicKeyshareElement.multiply(clientPrivateScalar);

	const ikm = concatBytes(
		suite.encodeElement(dh1),
		suite.encodeElement(dh2),
		suite.encodeElement(dh3),
	);

	const preamble = buildPreamble(
		cleartextCredentials.clientIdentity,
		state.ke1,
		cleartextCredentials.serverIdentity,
		credentialResponse,
		serverNonce,
		serverPublicKeyshare,
		context ?? EMPTY_BUFFER,	// Optional, but recommended
	);

	const { km2, km3, sessionKey } = deriveKeys(suite, ikm, preamble);
	const expectedServerMac = hmac(suite.hash, km2, suite.hash(preamble));
	if (!equalBytes(expectedServerMac, serverMac))
		throw new ServerAuthenticationError();

	const clientMac = hmac(suite.hash, km3, suite.hash(concatBytes(
		preamble, expectedServerMac,
	)));

	return {
		sessionKey,
		ke3: clientMac,
	};
}

function authServerFinalize<T extends CurvePoint<any, T>>(config: ServerConfig<T>, state: ServerState, ke3: KE3): Uint8Array {
	const [ clientMac ] = splitByteFields(ke3, [ config.suite.Nm ]);
	if (!equalBytes(state.expectedClientMac, clientMac))
		throw new ClientAuthenticationError();
	return state.sessionKey;
}

type GenerateKE1Options = AuthClientStartOptions & CreateCredentialRequestOptions;
type GenerateKE2Options = AuthServerRespondOptions & CreateCredentialOptions;

interface ClientFinishLoginResult {
	sessionKey: Uint8Array,
	exportKey: Uint8Array,
	ke3: KE3,
}

const EMPTY_SALT = new Uint8Array(16);
function defaultStretch<T extends CurvePoint<any, T>>(suite: Suite<T>, msg: Uint8Array): Promise<Uint8Array> {
	anumber(suite.Nh); abytes(msg);
	return argon2idAsync(msg, EMPTY_SALT, { dkLen: suite.Nh, p: 4, m: 2048, t: 1 });
}


export interface ClientState {
	password?: Uint8Array,
	blind?: Uint8Array,
	clientSecret?: Uint8Array,
	ke1?: KE1,
}

export interface ServerState {
	expectedClientMac?: Uint8Array,
	sessionKey?: Uint8Array,
}

type CommonOpts = {
	context?: Uint8Array,
};

export type ServerOpts = CommonOpts & { /* no additional params */ };
export type ClientOpts = CommonOpts & {
	stretch?(msg: Uint8Array): Promise<Uint8Array>,
};


export type Client<T extends CurvePoint<any, T>> = ClientOpts & {
	suite: Readonly<Suite<T>>,
	createRegistrationRequest(password: Uint8Array, options?: CreateRegistrationOptions): CreateCredentialRequestResult,
	finalizeRegistrationRequest(password: Uint8Array, blind: Uint8Array, response: RegistrationResponse, serverIdentity?: Uint8Array, clientIdentity?: Uint8Array, options?: FinalizeRegistrationOptions): Promise<FinalizeRegistrationResult>,
	createLoginRequest(state: ClientState, password: Uint8Array, options?: GenerateKE1Options): KE1,
	clientFinishLogin(state: ClientState, response: KE2, serverIdentity?: Uint8Array, clientIdentity?: Uint8Array): Promise<ClientFinishLoginResult>,
};

export function createClient<T extends CurvePoint<any, T>>(suite: Suite<T>, opts: ClientOpts): Client<T> {
	const config = { suite, stretch: (msg) => defaultStretch(suite, msg), ...(opts ?? {}) } as ClientConfig<T>;
	return Object.freeze({
		suite, ...opts,
		createRegistrationRequest(password, options) {
			return createRegistrationRequest(config, password, options);
		},
		finalizeRegistrationRequest(password, blind, response, serverIdentity, clientIdentity, options) {
			return finalizeRegistrationRequest(config, password, blind, response, serverIdentity, clientIdentity, options);
		},
		createLoginRequest(state, password, options) {
			const { request, blind } = createCredentialRequest(config, password, options as CreateCredentialRequestOptions);
			state.password = password;
			state.blind = blind;
			return authClientStart(config, state, request, options as AuthClientStartOptions);
		},
		async clientFinishLogin(state, response, serverIdentity, clientIdentity) {
			const [ credentialResponse ] = splitByteFields(response, [
				suite.Noe + suite.Nn + suite.Npk + suite.Nn + suite.Nm,	// CredentialResponse
				suite.Nn + suite.Npk + suite.Nm,						// AuthResponse
			]);
			const { clientSecretKey, cleartextCredentials, exportKey } = await recoverCredentials(config, state.password, state.blind, credentialResponse, serverIdentity, clientIdentity);
			const { ke3, sessionKey } = authClientFinalize(config, state, cleartextCredentials, clientSecretKey, response);
			return {
				ke3,
				exportKey,
				sessionKey,
			};
		},
	});
}

export type Server<T extends CurvePoint<any, T>> = ServerOpts & {
	suite: Readonly<Suite<T>>,
	randomSeed(): Uint8Array,
	randomKeypair(): Keypair,
	createRegistrationResponse(request: RegistrationRequest, serverPublicKey: Uint8Array, credentialIdentifier: Uint8Array, oprfSeed: Uint8Array): RegistrationResponse,
	createLoginResponse(state: ServerState, serverKeypair: Keypair, record: RegistrationRecord, credentialIdentifier: Uint8Array, oprfSeed: Uint8Array, request: KE1,
		serverIdentity?: Uint8Array, clientIdentity?: Uint8Array, options?: GenerateKE2Options): KE2,
	serverFinishLogin(state: ServerState, request: KE3): Uint8Array,
};

export function createServer<T extends CurvePoint<any, T>>(suite: Suite<T>, opts?: ServerOpts): Server<T> {
	const config = { suite, ...(opts ?? {}) } as ServerConfig<T>;
	return Object.freeze({
		suite, ...opts,
		randomSeed: () => randomBytes(suite.Nseed),
		randomKeypair: () => suite.oprf.randomKeypair(),
		createRegistrationResponse(serverKeypair, record, credetentialIdentifier, oprfSeed) {
			return createRegistrationResponse(config, serverKeypair, record, credetentialIdentifier, oprfSeed);
		},
		createLoginResponse(state, serverKeypair, record, credentialIdentifier, oprfSeed, request, serverIdentity, clientIdentity, options) {
			const credentialResponse = createCredentialResponse(config, request, serverKeypair.publicKey, record, credentialIdentifier, oprfSeed, options as CreateCredentialOptions);
			const [ clientPublicKey ] = splitByteFields(record, [ suite.Npk, suite.Nn, suite.Nm ]);
			const cleartextCredentials = createCleartextCredentials(serverKeypair.publicKey, clientPublicKey, serverIdentity, clientIdentity);
			const authResponse = authServerRespond(config, state, cleartextCredentials, serverKeypair.secretKey, clientPublicKey, request, credentialResponse, options as AuthServerRespondOptions);

			return concatBytes(
				credentialResponse,
				authResponse,
			);
		},
		serverFinishLogin(state, request) {
			return authServerFinalize(config, state, request);
		},
	});
}
