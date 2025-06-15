import { sha512 } from "@noble/hashes/sha2.js";

import { createClient, createServer, createSuite, ClientOpts, ServerOpts, type ClientState } from './_nopaque.mjs';
import { OPRF as OprfP521 } from "../oprf/p521.mjs";
export { type ClientState };

const suite = createSuite({
	oprf: OprfP521,
	hash: sha512,
	Nh: sha512.outputLen,
	Nseed: 64,
	Npk: 67,
	Nsk: 66,
	Nok: 64,
	Noe: 67,
	Nm: 64,
	Nn: 64,
	Nx: 64,
});

export const client = (opts?: ClientOpts) => createClient(suite, opts);
export const server = (opts?: ServerOpts) => createServer(suite, opts);
