import { use } from 'chai';
import chaibytes from 'chai-bytes';
import { describe, it } from 'mocha';

import { client, server } from "../../../src/nopaque/p521.mjs";
import { runRoundtripTest } from './_nopaque.mjs';

use(chaibytes);

describe("Nopaque-P521-SHA512", () => {
	it("Roundtrip", () => runRoundtripTest(client(), server()));
});
