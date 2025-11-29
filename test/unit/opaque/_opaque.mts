import { expect, use } from 'chai';
import chaibytes from 'chai-bytes';

import { CurvePoint } from '@noble/curves/abstract/curve.js';
import { utf8ToBytes } from "@noble/curves/utils.js";
import { type ClientState, type ServerState } from "../../../src/opaque/ristretto255.mjs";
import { ClientOpts, Client, Server, ServerOpts } from '../../../src/opaque/_opaque.mjs';
import { Keypair } from '../../../src/oprf/_oprf.mjs';

use(chaibytes);

export async function runRoundtripTest<T extends CurvePoint<any, T>>(client: Client<T>, server: Server<T>) {
	const password = server.randomSeed();
	const credentialId = utf8ToBytes("client123");

	const regReq = client.createRegistrationRequest(password);
	const serverKeypair = server.randomKeypair();
	const oprfSeed = server.randomSeed();	// Nh bytes of seed
	const regReply = server.createRegistrationResponse(regReq.request, serverKeypair.publicKey, credentialId, oprfSeed);
	const { exportKey, record: clientRecord } = await client.finalizeRegistrationRequest(password, regReq.blind, regReply);
	const serverRecord = {
		record: clientRecord,
		serverKeypair,
		oprfSeed,
	};

	const clientState: ClientState = {};
	const serverState: ServerState = {};
	const ke1 = client.createLoginRequest(clientState, password);
	const ke2 = server.createLoginResponse(serverState, serverRecord.serverKeypair, serverRecord.record, credentialId, serverRecord.oprfSeed, ke1);
	const { exportKey: recoveredExportKey, sessionKey: clientSessionKey, ke3 } = await client.clientFinishLogin(clientState, ke2);
	expect(recoveredExportKey, "'recoveredExportKey' does not match")
		.to.be.equalBytes(exportKey);

	const serverSessionKey = server.serverFinishLogin(serverState, ke3);
	expect(serverSessionKey, "'serverSessionKey' does not match")
		.to.be.equalBytes(clientSessionKey);
}

export type TestVector = {
	// Parameters
	clientIdentity?: Uint8Array,
	serverIdentity?: Uint8Array,
	context: Uint8Array,
	oprfSeed: Uint8Array,
	credentialId: Uint8Array,
	password: Uint8Array,
	envelopeNonce: Uint8Array,
	maskingNonce: Uint8Array,
	serverSecretKey: Uint8Array,
	serverPublicKey: Uint8Array,
	serverNonce: Uint8Array,
	clientNonce: Uint8Array,
	clientKeyshareSeed: Uint8Array,
	serverKeyshareSeed: Uint8Array,
	blindRegistration: Uint8Array,
	blindLogin: Uint8Array,
	// Intermediate values
	clientPublicKey: Uint8Array,
	authKey: Uint8Array,
	randomizedPassword: Uint8Array,
	envelope: Uint8Array,
	handshakeSecret: Uint8Array,
	serverMacKey: Uint8Array,
	clientMacKey: Uint8Array,
	oprfKey: Uint8Array,
	// Output values
	registrationRequest: Uint8Array,
	registrationResponse: Uint8Array,
	registrationUpload: Uint8Array,
	ke1: Uint8Array,
	ke2: Uint8Array,
	ke3: Uint8Array,
	exportKey: Uint8Array,
	sessionKey: Uint8Array,
};


export async function runTestVectors<T extends CurvePoint<any, T>>(vectors: TestVector[], clientFn: (opts: ClientOpts) => Client<T>, serverFn: (opts: ServerOpts) => Server<T>) {
	for (const vector of vectors) {
		const client = clientFn({ context: vector.context, stretch: async (msg) => msg });
		const server = serverFn({ context: vector.context });

		// registration
		const { blind: blindRegistration, request: registrationRequest } = client.createRegistrationRequest(vector.password, { blind: vector.blindRegistration });
		expect(blindRegistration, "'blindRegistration' does not match")
			.to.be.equalBytes(vector.blindRegistration);
		expect(registrationRequest, "'registrationRequest' does not match")
			.to.be.equalBytes(vector.registrationRequest);

		const serverKeypair = { secretKey: vector.serverSecretKey, publicKey: vector.serverPublicKey } as Keypair;
		const registrationResponse = server.createRegistrationResponse(registrationRequest, serverKeypair.publicKey, vector.credentialId, vector.oprfSeed);
		expect(registrationResponse, "'registrationResponse' does not match")
			.to.be.equalBytes(vector.registrationResponse);

		const { exportKey, record: registrationUpload } = await client.finalizeRegistrationRequest(vector.password, vector.blindRegistration, registrationResponse, vector.serverIdentity, vector.clientIdentity, { envelopeNonce: vector.envelopeNonce });
		expect(exportKey, "'exportKey' does not match")
			.to.be.equalBytes(vector.exportKey);
		expect(registrationUpload, "'registrationUpload' does not match")
			.to.be.equalBytes(vector.registrationUpload);


		// login
		const clientState: ClientState = {};
		const serverState: ServerState = {};
		const ke1 = client.createLoginRequest(clientState, vector.password, { clientNonce: vector.clientNonce, clientKeyshareSeed: vector.clientKeyshareSeed, blind: vector.blindLogin });
		expect(clientState.blind, "'blindLogin' does not match")
			.to.be.equalBytes(vector.blindLogin);
		expect(clientState.password, "'password' does not match")
			.to.be.equalBytes(vector.password);
		expect(ke1, "'KE1' does not match")
			.to.be.equalBytes(vector.ke1);

		const ke2 = server.createLoginResponse(serverState, serverKeypair, registrationUpload, vector.credentialId, vector.oprfSeed, ke1, vector.serverIdentity, vector.clientIdentity, {
			serverKeyshareSeed: vector.serverKeyshareSeed,
			serverNonce: vector.serverNonce,
			maskingNonce: vector.maskingNonce,
		});
		expect(ke2, "'KE2' does not match")
			.to.be.equalBytes(vector.ke2);

		const { exportKey: recoveredExportKey, sessionKey: clientSessionKey, ke3 } = await client.clientFinishLogin(clientState, ke2, vector.serverIdentity, vector.clientIdentity);
		expect(clientSessionKey, "'clientSessionKey' does not match")
			.to.be.equalBytes(vector.sessionKey);
		expect(recoveredExportKey, "'recoveredExportKey' does not match")
			.to.be.equalBytes(vector.exportKey);
		expect(ke3, "'KE3' does not match")
			.to.be.equalBytes(vector.ke3);

		const serverSessionKey = server.serverFinishLogin(serverState, ke3);
		expect(serverSessionKey, "'serverSessionKey' does not match")
			.to.be.equalBytes(vector.sessionKey);
	}
}
