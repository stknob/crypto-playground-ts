import { shake256 } from '@noble/hashes/sha3.js';

import { createClient, createServer, createSuite, ClientOpts, ServerOpts, type ClientState } from './_nopaque.mjs';
import { OPRF as OprfDecaf448 } from '../oprf/decaf448.mjs';
import { HashXOF, wrapConstructor } from '@noble/hashes/utils.js';
export { type ClientState };

const shake256_512 = wrapConstructor<HashXOF<any>>(() => shake256.create({ dkLen: 64 }));

const suite = createSuite({
	oprf: OprfDecaf448,
	hash: shake256_512,
	Nh: shake256_512.outputLen,
	Nseed: 64,
	Npk: 56,
	Nsk: 56,
	Nok: 56,
	Noe: 56,
	Nn: 64,
	Nm: 64,
	Nx: 64,
});

export const client = (opts?: ClientOpts) => createClient(suite, opts);
export const server = (opts?: ServerOpts) => createServer(suite, opts);
