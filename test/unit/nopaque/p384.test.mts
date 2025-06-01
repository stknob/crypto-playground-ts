import { describe, it } from 'mocha';

import { client, server } from "../../../src/nopaque/p384.mjs";
import { runRoundtripTest } from './_nopaque.mjs';

describe("Nopaque-P384-SHA384", () => {
    it("Roundtrip", () => runRoundtripTest(client(), server()));
});
