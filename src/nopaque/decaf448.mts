import { shake256_64 } from '@noble/hashes/sha3.js';

import { createClient, createServer, createSuite, ClientOpts, ServerOpts, type ClientState } from './_nopaque.mjs';
import { OPRF as OprfDecaf448 } from '../oprf/decaf448.mjs';
export { type ClientState };

const suite = createSuite({
	oprf: OprfDecaf448,
	hash: shake256_64,
	Nh: shake256_64.outputLen,
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
