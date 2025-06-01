import { describe, it } from 'mocha';

import { client, server } from "../../../src/nopaque/decaf448.mjs";
import { runRoundtripTest } from './_nopaque.mjs';

describe("Nopaque-Decaf448-SHAKE256", () => {
	it("Roundtrip", () => runRoundtripTest(client(), server()));
});
