import { describe, it } from 'mocha';

import { hexToBytes } from "@noble/curves/utils.js";
import { OPRF, VOPRF, POPRF } from "../../../src/oprf/decaf448.mjs";
import { BatchPoprfTestVector, BatchVoprfTestVector, MixedPoprfTestVector, MixedVoprfTestVector, OprfTestVector, runOPRFTests, runPOPRFTests, runVOPRFTests } from './_oprf.mjs';

const oprfTests: OprfTestVector[] = [{
    name: "decaf448-CSHAKE256 - OPRF - Test Vector 1, Batch Size 1",
    seed:    hexToBytes("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
    keyInfo: hexToBytes("74657374206b6579"),
    skS:     hexToBytes("e8b1375371fd11ebeb224f832dcc16d371b4188951c438f751425699ed29ecc80c6c13e558ccd67634fd82eac94aa8d1f0d7fee990695d1e"),
    input:   hexToBytes("00"),
    blind:   hexToBytes("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec65fa3833a26e9388336361686ff1f83df55046504dfecad8549ba112"),
    blindedElement:    hexToBytes("e0ae01c4095f08e03b19baf47ffdc19cb7d98e583160522a3c7d6a0b2111cd93a126a46b7b41b730cd7fc943d4e28e590ed33ae475885f6c"),
    evaluationElement: hexToBytes("50ce4e60eed006e22e7027454b5a4b8319eb2bc8ced609eb19eb3ad42fb19e06ba12d382cbe7ae342a0cad6ead0ef8f91f00bb7f0cd9c0a2"),
    output:  hexToBytes("37d3f7922d9388a15b561de5829bbf654c4089ede89c0ce0f3f85bcdba09e382ce0ab3507e021f9e79706a1798ffeac68ebd5cf62e5eb9838c7068351d97ae37"),
}, {
    name: "decaf448-CSHAKE256 - OPRF - Test Vector 2, Batch Size 1",
    seed:    hexToBytes("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
    keyInfo: hexToBytes("74657374206b6579"),
    skS:     hexToBytes("e8b1375371fd11ebeb224f832dcc16d371b4188951c438f751425699ed29ecc80c6c13e558ccd67634fd82eac94aa8d1f0d7fee990695d1e"),
    input:   hexToBytes("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"),
    blind:   hexToBytes("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec65fa3833a26e9388336361686ff1f83df55046504dfecad8549ba112"),
    blindedElement:    hexToBytes("86a88dc5c6331ecfcb1d9aacb50a68213803c462e377577cacc00af28e15f0ddbc2e3d716f2f39ef95f3ec1314a2c64d940a9f295d8f13bb"),
    evaluationElement: hexToBytes("162e9fa6e9d527c3cd734a31bf122a34dbd5bcb7bb23651f1768a7a9274cc116c03b58afa6f0dede3994a60066c76370e7328e7062fd5819"),
    output:  hexToBytes("a2a652290055cb0f6f8637a249ee45e32ef4667db0b4c80c0a70d2a64164d01525cfdad5d870a694ec77972b9b6ec5d2596a5223e5336913f945101f0137f55e"),
}];

const voprfTests: MixedVoprfTestVector[] = [{
    name: "decaf448-SHAKE256 - VOPRF - Test Vector 1, Batch Size 1",
    seed:    hexToBytes("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
    keyInfo: hexToBytes("74657374206b6579"),
    skS:     hexToBytes("e3c01519a076a326a0eb566343e9b21c115fa18e6e85577ddbe890b33104fcc2835ddfb14a928dc3f5d79b936e17c76b99e0bf6a1680930e"),
    pkS:     hexToBytes("945fc518c47695cf65217ace04b86ac5e4cbe26ca649d52854bb16c494ce09069d6add96b20d4b0ae311a87c9a73e3a146b525763ab2f955"),
    input:   hexToBytes("00"),
    blind:   hexToBytes("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec65fa3833a26e9388336361686ff1f83df55046504dfecad8549ba112"),
    blindedElement:    hexToBytes("7261bbc335c664ba788f1b1a1a4cd5190cc30e787ef277665ac1d314f8861e3ec11854ce3ddd42035d9e0f5cddde324c332d8c880abc00eb"),
    evaluationElement: hexToBytes("ca1491a526c28d880806cf0fb0122222392cf495657be6e4c9d203bceffa46c86406caf8217859d3fb259077af68e5d41b3699410781f467"),
    proof:   hexToBytes("f84bbeee47aedf43558dae4b95b3853635a9fc1a9ea7eac9b454c64c66c4f49cd1c72711c7ac2e06c681e16ea693d5500bbd7b56455df52f69e00b76b4126961e1562fdbaaac40b7701065cbeece3febbfe09e00160f81775d36daed99d8a2a10be0759e01b7ee81217203416c9db208"),
    proofRandomScalar: hexToBytes("b1b748135d405ce48c6973401d9455bb8ccd18b01d0295c0627f67661200dbf9569f73fbb3925daa043a070e5f953d80bb464ea369e5522b"),
    output:  hexToBytes("e2ac40b634f36cccd8262b285adff7c9dcc19cd308564a5f4e581d1a8535773b86fa4fc9f2203c370763695c5093aea4a7aedec4488b1340ba3bf663a23098c1"),
}, {
    name: "decaf448-SHAKE256 - VOPRF - Test Vector 2, Batch Size 1",
    seed:    hexToBytes("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
    keyInfo: hexToBytes("74657374206b6579"),
    skS:     hexToBytes("e3c01519a076a326a0eb566343e9b21c115fa18e6e85577ddbe890b33104fcc2835ddfb14a928dc3f5d79b936e17c76b99e0bf6a1680930e"),
    pkS:     hexToBytes("945fc518c47695cf65217ace04b86ac5e4cbe26ca649d52854bb16c494ce09069d6add96b20d4b0ae311a87c9a73e3a146b525763ab2f955"),
    input:   hexToBytes("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"),
    blind:   hexToBytes("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec65fa3833a26e9388336361686ff1f83df55046504dfecad8549ba112"),
    blindedElement:    hexToBytes("88287e553939090b888ddc15913e1807dc4757215555e1c3a79488ef311594729c7fa74c772a732b78440b7d66d0aa35f3bb316f1d93e1b2"),
    evaluationElement: hexToBytes("c00978c73e8e4ee1d447ab0d3ad1754055e72cc85c08e3a0db170909a9c61cbff1f1e7015f289e3038b0f341faea5d7780c130106065c231"),
    proof:   hexToBytes("7a2831a6b237e11ac1657d440df93bc5ce00f552e6020a99d5c956ffc4d07b5ade3e82ecdc257fd53d76239e733e0a1313e84ce16cc0d82734806092a693d7e8d3c420c2cb6ccd5d0ca32514fb78e9ad0973ebdcb52eba438fc73948d76339ee710121d83e2fe6f001cfdf551aff9f36"),
    proofRandomScalar: hexToBytes("b1b748135d405ce48c6973401d9455bb8ccd18b01d0295c0627f67661200dbf9569f73fbb3925daa043a070e5f953d80bb464ea369e5522b"),
    output:  hexToBytes("862952380e07ec840d9f6e6f909c5a25d16c3dacb586d89a181b4aa7380c959baa8c480fe8e6c64e089d68ea7aeeb5817bd524d7577905b5bab487690048c941"),
}, {
    name: "decaf448-SHAKE256 - VOPRF - Test Vector 3, Batch Size 2",
    seed:    hexToBytes("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
    keyInfo: hexToBytes("74657374206b6579"),
    skS:     hexToBytes("e3c01519a076a326a0eb566343e9b21c115fa18e6e85577ddbe890b33104fcc2835ddfb14a928dc3f5d79b936e17c76b99e0bf6a1680930e"),
    pkS:     hexToBytes("945fc518c47695cf65217ace04b86ac5e4cbe26ca649d52854bb16c494ce09069d6add96b20d4b0ae311a87c9a73e3a146b525763ab2f955"),
    input:   [
        hexToBytes("00"),
        hexToBytes("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"),
    ],
    blind: [
        hexToBytes("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec65fa3833a26e9388336361686ff1f83df55046504dfecad8549ba112"),
        hexToBytes("b1b748135d405ce48c6973401d9455bb8ccd18b01d0295c0627f67661200dbf9569f73fbb3925daa043a070e5f953d80bb464ea369e5522b"),
    ],
    blindedElement: [
        hexToBytes("7261bbc335c664ba788f1b1a1a4cd5190cc30e787ef277665ac1d314f8861e3ec11854ce3ddd42035d9e0f5cddde324c332d8c880abc00eb"),
        hexToBytes("2e15f393c035492a1573627a3606e528c6294c767c8d43b8c691ef70a52cc7dc7d1b53fe458350a270abb7c231b87ba58266f89164f714d9"),
    ],
    evaluationElement: [
        hexToBytes("ca1491a526c28d880806cf0fb0122222392cf495657be6e4c9d203bceffa46c86406caf8217859d3fb259077af68e5d41b3699410781f467"),
        hexToBytes("8ec68e9871b296e81c55647ce64a04fe75d19932f1400544cd601468c60f998408bbb546601d4a636e8be279e558d70b95c8d4a4f61892be"),
    ],
    proof:   hexToBytes("167d922f0a6ffa845eed07f8aa97b6ac746d902ecbeb18f49c009adc0521eab1e4d275b74a2dc266b7a194c854e85e7eb54a9a36376dfc04ec7f3bd55fc9618c3970cb548e064f8a2f06183a5702933dbc3e4c25a73438f2108ee1981c306181003c7ea92fce963ec7b4ba4f270e6d38"),
    proofRandomScalar: hexToBytes("63798726803c9451ba405f00ef3acb633ddf0c420574a2ec6cbf28f840800e355c9fbaac10699686de2724ed22e797a00f3bd93d105a7f23"),
    output: [
        hexToBytes("e2ac40b634f36cccd8262b285adff7c9dcc19cd308564a5f4e581d1a8535773b86fa4fc9f2203c370763695c5093aea4a7aedec4488b1340ba3bf663a23098c1"),
        hexToBytes("862952380e07ec840d9f6e6f909c5a25d16c3dacb586d89a181b4aa7380c959baa8c480fe8e6c64e089d68ea7aeeb5817bd524d7577905b5bab487690048c941"),
    ],
} as BatchVoprfTestVector];

const poprfTests: MixedPoprfTestVector[] = [{
    name: "decaf448-SHAKE256 - POPRF - Test Vector 1, Batch Size 1",
    seed:    hexToBytes("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
    keyInfo: hexToBytes("74657374206b6579"),
    skS:     hexToBytes("792a10dcbd3ba4a52a054f6f39186623208695301e7adb9634b74709ab22de402990eb143fd7c67ac66be75e0609705ecea800992aac8e19"),
    pkS:     hexToBytes("6c9d12723a5bbcf305522cc04b4a34d9ced2e12831826018ea7b5dcf5452647ad262113059bf0f6e4354319951b9d513c74f29cb0eec38c1"),
    info:    hexToBytes("7465737420696e666f"),
    input:   hexToBytes("00"),
    blind:   hexToBytes("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec65fa3833a26e9388336361686ff1f83df55046504dfecad8549ba112"),
    blindedElement:    hexToBytes("161183c13c6cb33b0e4f9b7365f8c5c12d13c72f8b62d276ca09368d093dce9b42198276b9e9d870ac392dda53efd28d1b7e6e8c060cdc42"),
    evaluationElement: hexToBytes("06ec89dfde25bb2a6f0145ac84b91ac277b35de39ad1d6f402a8e46414952ce0d9ea1311a4ece283e2b01558c7078b040cfaa40dd63b3e6c"),
    proof:   hexToBytes("66caee75bf2460429f620f6ad3e811d524cb8ddd848a435fc5d89af48877abf6506ee341a0b6f67c2d76cd021e5f3d1c9abe5aa9f0dce016da746135fedba2af41ed1d01659bfd6180d96bc1b7f320c0cb6926011ce392ecca748662564892bae66516acaac6ca39aadf6fcca95af406"),
    proofRandomScalar: hexToBytes("b1b748135d405ce48c6973401d9455bb8ccd18b01d0295c0627f67661200dbf9569f73fbb3925daa043a070e5f953d80bb464ea369e5522b"),
    output:  hexToBytes("4423f6dcc1740688ea201de57d76824d59cd6b859e1f9884b7eebc49b0b971358cf9cb075df1536a8ea31bcf55c3e31c2ba9cfa8efe54448d17091daeb9924ed"),
}, {
    name: "decaf448-SHAKE256 - POPRF - Test Vector 2, Batch Size 1",
    seed:    hexToBytes("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
    keyInfo: hexToBytes("74657374206b6579"),
    skS:     hexToBytes("792a10dcbd3ba4a52a054f6f39186623208695301e7adb9634b74709ab22de402990eb143fd7c67ac66be75e0609705ecea800992aac8e19"),
    pkS:     hexToBytes("6c9d12723a5bbcf305522cc04b4a34d9ced2e12831826018ea7b5dcf5452647ad262113059bf0f6e4354319951b9d513c74f29cb0eec38c1"),
    info:    hexToBytes("7465737420696e666f"),
    input:   hexToBytes("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"),
    blind:   hexToBytes("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec65fa3833a26e9388336361686ff1f83df55046504dfecad8549ba112"),
    blindedElement:    hexToBytes("12082b6a381c6c51e85d00f2a3d828cdeab3f5cb19a10b9c014c33826764ab7e7cfb8b4ff6f411bddb2d64e62a472af1cd816e5b712790c6"),
    evaluationElement: hexToBytes("f2919b7eedc05ab807c221fce2b12c4ae9e19e6909c4784564b690d1972d2994ca623f273afc67444d84ea40cbc58fcdab7945f321a52848"),
    proof:   hexToBytes("a295677c54d1bc4286330907fc2490a7de163da26f9ce03a462a452fea422b19ade296ba031359b3b6841e48455d20519ad01b4ac4f0b92e76d3cf16fbef0a3f72791a8401ef2d7081d361e502e96b2c60608b9fa566f43d4611c2f161d83aabef7f8017332b26ed1daaf80440772022"),
    proofRandomScalar: hexToBytes("b1b748135d405ce48c6973401d9455bb8ccd18b01d0295c0627f67661200dbf9569f73fbb3925daa043a070e5f953d80bb464ea369e5522b"),
    output:  hexToBytes("8691905500510843902c44bdd9730ab9dc3925aa58ff9dd42765a2baf633126de0c3adb93bef5652f38e5827b6396e87643960163a560fc4ac9738c8de4e4a8d"),
}, {
    name: "decaf448-SHAKE256 - POPRF - Test Vector 3, Batch Size 2",
    seed:    hexToBytes("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
    keyInfo: hexToBytes("74657374206b6579"),
    skS:     hexToBytes("792a10dcbd3ba4a52a054f6f39186623208695301e7adb9634b74709ab22de402990eb143fd7c67ac66be75e0609705ecea800992aac8e19"),
    pkS:     hexToBytes("6c9d12723a5bbcf305522cc04b4a34d9ced2e12831826018ea7b5dcf5452647ad262113059bf0f6e4354319951b9d513c74f29cb0eec38c1"),
    info:    hexToBytes("7465737420696e666f"),
    input:   [
        hexToBytes("00"),
        hexToBytes("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"),
    ],
    blind: [
        hexToBytes("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec65fa3833a26e9388336361686ff1f83df55046504dfecad8549ba112"),
        hexToBytes("b1b748135d405ce48c6973401d9455bb8ccd18b01d0295c0627f67661200dbf9569f73fbb3925daa043a070e5f953d80bb464ea369e5522b"),
    ],
    blindedElement: [
        hexToBytes("161183c13c6cb33b0e4f9b7365f8c5c12d13c72f8b62d276ca09368d093dce9b42198276b9e9d870ac392dda53efd28d1b7e6e8c060cdc42"),
        hexToBytes("fc8847d43fb4cea4e408f585661a8f2867533fa91d22155d3127a22f18d3b007add480f7d300bca93fa47fe87ae06a57b7d0f0d4c30b12f0"),
    ],
    evaluationElement: [
        hexToBytes("06ec89dfde25bb2a6f0145ac84b91ac277b35de39ad1d6f402a8e46414952ce0d9ea1311a4ece283e2b01558c7078b040cfaa40dd63b3e6c"),
        hexToBytes("2e74c626d07de49b1c8c21d87120fd78105f485e36816af9bde3e3efbeef76815326062fd333925b66c5ce5a20f100bf01770c16609f990a"),
    ],
    proof:   hexToBytes("fd94db736f97ea4efe9d0d4ad2933072697a6bbeb32834057b23edf7c7009f011dfa72157f05d2a507c2bbf0b54cad99ab99de05921c021fda7d70e65bcecdb05f9a30154127ace983c74d10fd910b554c5e95f6bd1565fd1f3dbbe3c523ece5c72d57a559b7be1368c4786db4a3c910"),
    proofRandomScalar: hexToBytes("63798726803c9451ba405f00ef3acb633ddf0c420574a2ec6cbf28f840800e355c9fbaac10699686de2724ed22e797a00f3bd93d105a7f23"),
    output: [
        hexToBytes("4423f6dcc1740688ea201de57d76824d59cd6b859e1f9884b7eebc49b0b971358cf9cb075df1536a8ea31bcf55c3e31c2ba9cfa8efe54448d17091daeb9924ed"),
        hexToBytes("8691905500510843902c44bdd9730ab9dc3925aa58ff9dd42765a2baf633126de0c3adb93bef5652f38e5827b6396e87643960163a560fc4ac9738c8de4e4a8d"),
    ],
} as BatchPoprfTestVector];

describe("decaf448-CSHAKE256", () => {
    it('OPRF RFC9497 test vectors',  () => runOPRFTests(OPRF, oprfTests));
    it('VOPRF RFC9497 test vectors', () => runVOPRFTests(VOPRF, voprfTests));
    it('POPRF RFC9497 test vectors', () => runPOPRFTests(POPRF, poprfTests));
});
