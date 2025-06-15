import { sha512 } from '@noble/hashes/sha2.js';

import { createClient, createServer, createSuite, ClientOpts, ServerOpts, type ClientState, type ServerState } from './_opaque.mjs';
import { OPRF as OprfRistretto255 } from '../oprf/ristretto255.mjs';
export { type ClientState, type ServerState };

const suite = createSuite({
	oprf: OprfRistretto255,
	hash: sha512,
	Nh: sha512.outputLen,
	Nseed: 32,
	Npk: 32,
	Nsk: 32,
	Noe: 32,
	Nok: 32,
	Nn: 32,
	Nm: 64,
	Nx: 64,
});

export const client = (opts?: ClientOpts) => createClient(suite, opts);
export const server = (opts?: ServerOpts) => createServer(suite, opts);
