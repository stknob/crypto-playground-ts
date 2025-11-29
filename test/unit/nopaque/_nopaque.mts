import { use, expect } from 'chai';
import chaibytes from 'chai-bytes';

import { CurvePoint } from '@noble/curves/abstract/curve.js';
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { type ClientState } from "../../../src/nopaque/ristretto255.mjs";
import { Client, ClientOpts, Server, ServerOpts } from '../../../src/nopaque/_nopaque.mjs';
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
    const ke1 = client.createRecoverRequest(clientState, password);
    const ke2 = server.createRecoverResponse(serverRecord.serverKeypair, serverRecord.record, credentialId, serverRecord.oprfSeed, ke1);
    const recoveredExportKey = await client.finalizeRecoverRequest(clientState, ke2);
    expect(recoveredExportKey, "'recoveredExportKey' does not match")
        .to.be.equalBytes(exportKey);
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
	blindRegistration: Uint8Array,
	blindLogin: Uint8Array,
	// Intermediate values
	clientPublicKey: Uint8Array,
	authKey: Uint8Array,
	randomizedPassword: Uint8Array,
	envelope: Uint8Array,
	handshakeSecret: Uint8Array,
	oprfKey: Uint8Array,
	// Output values
	registrationRequest: Uint8Array,
	registrationResponse: Uint8Array,
	registrationUpload: Uint8Array,
	recoverRequest: Uint8Array,
	recoverResponse: Uint8Array,
	exportKey: Uint8Array,
};


export async function runTestVectors<T extends CurvePoint<any, T>>(vectors: TestVector[], clientFn: (opts: ClientOpts) => Client<T>, serverFn: (opts: ServerOpts) => Server<T>) {
	for (const vector of vectors) {
		const client = clientFn({ stretch: async (msg) => msg, customDeriveDhKeyPairLabel: utf8ToBytes("OPAQUE-DeriveDiffieHellmanKeyPair"), });
		const server = serverFn({ customDeriveKeyPairLabel: utf8ToBytes("OPAQUE-DeriveKeyPair"), });

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
		const recoverRequest = client.createRecoverRequest(clientState, vector.password, { blind: vector.blindLogin });
		expect(clientState.blind, "'blindLogin' does not match")
			.to.be.equalBytes(vector.blindLogin);
		expect(clientState.password, "'password' does not match")
			.to.be.equalBytes(vector.password);
		expect(recoverRequest, "'recoverRequest' does not match")
			.to.be.equalBytes(vector.recoverRequest);

		const recoverResponse = server.createRecoverResponse(serverKeypair, registrationUpload, vector.credentialId, vector.oprfSeed, recoverRequest, { maskingNonce: vector.maskingNonce });
		expect(recoverResponse, "'recoverResponse' does not match")
			.to.be.equalBytes(vector.recoverResponse);

		const recoveredExportKey = await client.finalizeRecoverRequest(clientState, recoverResponse, vector.serverIdentity, vector.clientIdentity);
		expect(recoveredExportKey, "'recoveredExportKey' does not match")
			.to.be.equalBytes(vector.exportKey);
	}
}
