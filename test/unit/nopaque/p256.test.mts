import { describe, it } from 'mocha';

import { client, server } from "../../../src/nopaque/p256.mjs";
import { TestVector, runRoundtripTest, runTestVectors } from './_nopaque.mjs';
import { hexToBytes } from '@noble/curves/abstract/utils';

const vectors: TestVector[] = [{
	// D.1.5. OPAQUE-3DH Real Test Vector 5
	// Input parameters
	context: hexToBytes("4f50415155452d504f43"),
	oprfSeed: hexToBytes("62f60b286d20ce4fd1d64809b0021dad6ed5d52a2c8cf27ae6582543a0a8dce2"),
	credentialId: hexToBytes("31323334"),
	password: hexToBytes("436f7272656374486f72736542617474657279537461706c65"),
	envelopeNonce: hexToBytes("a921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51f"),
	maskingNonce: hexToBytes("38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d"),
	serverSecretKey: hexToBytes("c36139381df63bfc91c850db0b9cfbec7a62e86d80040a41aa7725bf0e79d5e5"),
	serverPublicKey: hexToBytes("035f40ff9cf88aa1f5cd4fe5fd3da9ea65a4923a5594f84fd9f2092d6067784874"),
	blindRegistration: hexToBytes("411bf1a62d119afe30df682b91a0a33d777972d4f2daa4b34ca527d597078153"),
	blindLogin: hexToBytes("c497fddf6056d241e6cf9fb7ac37c384f49b357a221eb0a802c989b9942256c1"),
	// Intermediate values
	clientPublicKey: hexToBytes("03b218507d978c3db570ca994aaf36695a731ddb2db272c817f79746fc37ae5214"),
	authKey: hexToBytes("5bd4be1602516092dc5078f8d699f5721dc1720a49fb80d8e5c16377abd0987b"),
	randomizedPassword: hexToBytes("06be0a1a51d56557a3adad57ba29c5510565dcd8b5078fa319151b9382258fb0"),
	envelope: hexToBytes("a921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51fad30bbcfc1f8eda0211553ab9aaf26345ad59a128e80188f035fe4924fad67b8"),
	handshakeSecret: hexToBytes("83a932431a8f25bad042f008efa2b07c6cd0faa8285f335b6363546a9f9b235f"),
	oprfKey: hexToBytes("2dfb5cb9aa1476093be74ca0d43e5b02862a05f5d6972614d7433acdc66f7f31"),
	// Output values
	registrationRequest: hexToBytes("029e949a29cfa0bf7c1287333d2fb3dc586c41aa652f5070d26a5315a1b50229f8"),
	registrationResponse: hexToBytes("0350d3694c00978f00a5ce7cd08a00547e4ab5fb5fc2b2f6717cdaa6c89136efef035f40ff9cf88aa1f5cd4fe5fd3da9ea65a4923a5594f84fd9f2092d6067784874"),
	registrationUpload: hexToBytes("03b218507d978c3db570ca994aaf36695a731ddb2db272c817f79746fc37ae52147f0ed53532d3ae8e505ecc70d42d2b814b6b0e48156def71ea029148b2803aafa921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51fad30bbcfc1f8eda0211553ab9aaf26345ad59a128e80188f035fe4924fad67b8"),
	recoverRequest: hexToBytes("037342f0bcb3ecea754c1e67576c86aa90c1de3875f390ad599a26686cdfee6e07"),
	recoverResponse: hexToBytes("0246da9fe4d41d5ba69faa6c509a1d5bafd49a48615a47a8dd4b0823cc1476481138fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d2f0c547f70deaeca54d878c14c1aa5e1ab405dec833777132eea905c2fbb12504a67dcbe0e66740c76b62c13b04a38a77926e19072953319ec65e41f9bfd2ae26837b6ce688bf9af2542f04eec9ab96a1b9328812dc2f5c89182ed47fead61f09f"),
	exportKey: hexToBytes("c3c9a1b0e33ac84dd83d0b7e8af6794e17e7a3caadff289fbd9dc769a853c64b"),
}, {
	// D.1.6. OPAQUE-3DH Real Test Vector 6
	// Input parameters
	clientIdentity: hexToBytes("616c696365"),
	serverIdentity: hexToBytes("626f62"),
	context: hexToBytes("4f50415155452d504f43"),
	oprfSeed: hexToBytes("62f60b286d20ce4fd1d64809b0021dad6ed5d52a2c8cf27ae6582543a0a8dce2"),
	credentialId: hexToBytes("31323334"),
	password: hexToBytes("436f7272656374486f72736542617474657279537461706c65"),
	envelopeNonce: hexToBytes("a921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51f"),
	maskingNonce: hexToBytes("38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d"),
	serverSecretKey: hexToBytes("c36139381df63bfc91c850db0b9cfbec7a62e86d80040a41aa7725bf0e79d5e5"),
	serverPublicKey: hexToBytes("035f40ff9cf88aa1f5cd4fe5fd3da9ea65a4923a5594f84fd9f2092d6067784874"),
	blindRegistration: hexToBytes("411bf1a62d119afe30df682b91a0a33d777972d4f2daa4b34ca527d597078153"),
	blindLogin: hexToBytes("c497fddf6056d241e6cf9fb7ac37c384f49b357a221eb0a802c989b9942256c1"),
	// Intermediate values
	clientPublicKey: hexToBytes("03b218507d978c3db570ca994aaf36695a731ddb2db272c817f79746fc37ae5214"),
	authKey: hexToBytes("5bd4be1602516092dc5078f8d699f5721dc1720a49fb80d8e5c16377abd0987b"),
	randomizedPassword: hexToBytes("06be0a1a51d56557a3adad57ba29c5510565dcd8b5078fa319151b9382258fb0"),
	envelope: hexToBytes("a921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51f4d7773a36a208a866301dbb2858e40dc5638017527cf91aef32d3848eebe0971"),
	handshakeSecret: hexToBytes("80bdcc498f22de492e90ee8101fcc7c101e158dd49c77f7c283816ae329ed62f"),
	oprfKey: hexToBytes("2dfb5cb9aa1476093be74ca0d43e5b02862a05f5d6972614d7433acdc66f7f31"),
	// Output values
	registrationRequest: hexToBytes("029e949a29cfa0bf7c1287333d2fb3dc586c41aa652f5070d26a5315a1b50229f8"),
	registrationResponse: hexToBytes("0350d3694c00978f00a5ce7cd08a00547e4ab5fb5fc2b2f6717cdaa6c89136efef035f40ff9cf88aa1f5cd4fe5fd3da9ea65a4923a5594f84fd9f2092d6067784874"),
	registrationUpload: hexToBytes("03b218507d978c3db570ca994aaf36695a731ddb2db272c817f79746fc37ae52147f0ed53532d3ae8e505ecc70d42d2b814b6b0e48156def71ea029148b2803aafa921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51f4d7773a36a208a866301dbb2858e40dc5638017527cf91aef32d3848eebe0971"),
	recoverRequest: hexToBytes("037342f0bcb3ecea754c1e67576c86aa90c1de3875f390ad599a26686cdfee6e07"),
	recoverResponse: hexToBytes("0246da9fe4d41d5ba69faa6c509a1d5bafd49a48615a47a8dd4b0823cc1476481138fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d2f0c547f70deaeca54d878c14c1aa5e1ab405dec833777132eea905c2fbb12504a67dcbe0e66740c76b62c13b04a38a77926e19072953319ec65e41f9bfd2ae268d7f106042021c80300e4c6f585980cf39fc51a4a6bba41b0729f9b240c729e56"),
	exportKey: hexToBytes("c3c9a1b0e33ac84dd83d0b7e8af6794e17e7a3caadff289fbd9dc769a853c64b"),
}];

describe("Nopaque-P256-SHA256", () => {
	it("Roundtrip", () => runRoundtripTest(client(), server()));
	it("draft-irtf-cfrg-opaque-18", () => runTestVectors(vectors, client, server));
});
