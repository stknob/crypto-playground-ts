import { sha256 } from "@noble/hashes/sha2.js";

import { createClient, createServer, createSuite, type ClientState, ClientOpts, ServerOpts } from './_nopaque.mjs';
import { OPRF as OprfP256 } from "../oprf/p256.mjs";
export { type ClientState };

const suite = createSuite({
	oprf: OprfP256,
	hash: sha256,
	Nh: sha256.outputLen,
	Nseed: 32,
	Nok: 32,
	Noe: 33,
	Npk: 33,
	Nsk: 32,
	Nm: 32,
	Nn: 32,
	Nx: 32,
});

export const client = (opts?: ClientOpts) => createClient(suite, opts);
export const server = (opts?: ServerOpts) => createServer(suite, opts);
