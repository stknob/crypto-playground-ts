import { sha384 } from "@noble/hashes/sha2.js";

import { createClient, createServer, createSuite, ClientOpts, ServerOpts, type ClientState, type ServerState } from './_opaque.mjs';
import { OPRF as OprfP384Sha384 } from "../oprf/p384.mjs";
export { type ClientState, type ServerState };

const suite = createSuite({
	oprf: OprfP384Sha384,
	hash: sha384,
	Nh: sha384.outputLen,
	Nseed: 48,
	Npk: 49,
	Nsk: 48,
	Noe: 49,
	Nok: 48,
	Nm: 48,
	Nn: 48,
	Nx: 48,
});

export const client = (opts?: ClientOpts) => createClient(suite, opts);
export const server = (opts?: ServerOpts) => createServer(suite, opts);
