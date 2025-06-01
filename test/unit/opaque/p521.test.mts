import { describe, it } from 'mocha';

import { client, server } from "../../../src/opaque/p521.mjs";
import { runRoundtripTest } from './_opaque.mjs';

describe("Opaque-P521-SHA512", () => {
	it("Roundtrip", () => runRoundtripTest(client(), server()));
});
