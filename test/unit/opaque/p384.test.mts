import { describe, it } from 'mocha';

import { client, server } from "../../../src/opaque/p384.mjs";
import { runRoundtripTest } from './_opaque.mjs';

describe("Opaque-P384-SHA384", () => {
	it("Roundtrip", () => runRoundtripTest(client(), server()));
});
