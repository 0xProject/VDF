import {waffle} from '@nomiclabs/buidler';
import chai from 'chai';
import {deployContract, solidity} from 'ethereum-waffle';
import {utils, ethers} from 'ethers';

import VerifierTestingArtifact from '../artifacts/VerifierTesting.json';
import {VerifierTesting} from '../typechain/VerifierTesting';

chai.use(solidity);
const {expect} = chai;

describe('Verifier Testing', () => {
    let verifier: any;
    const init_hex = '0x0123456789abcded';

    const provider = waffle.provider;
    const [wallet] = provider.getWallets();

    before(async () => {
        verifier = (await deployContract(
            wallet,
            VerifierTestingArtifact,
        )) as VerifierTesting;
    });

    it('Should add big numbs correctly', async () => {
        // This first test is basic but uses both parts of the function.
        const c = await verifier.big_add_external(
            '0x00ffffff6c9b26d064d9364d9364d9364d9364d9364d9364d9364d9364d9364e',
            '0x00ffffff6c9b26d064d9364d9364d9364d9364d9364d9364d9364d9364d9364e',
        );
        expect(c).to.be.eq(
            '0x01fffffed9364da0c9b26c9b26c9b26c9b26c9b26c9b26c9b26c9b26c9b26c9c'.toLocaleLowerCase(),
        );
        // We will randomly sample much larger numbs for more cases
        for (let i = 0; i < 10; i++) {
            // 256 bytes is the target big numb rsa size
            const a = utils.randomBytes(256);
            const b = utils.randomBytes(256);
            verifier.big_add_external(a, b).then((c: any) => {
                expect(c).to.be.eq(
                    utils
                        .bigNumberify(a)
                        .add(utils.bigNumberify(b))
                        .toHexString(),
                );
            });
        }
    });

    it('Should sub big numbs correctly', async () => {
        // This first test is basic but uses both parts of the function.
        const c = await verifier.big_sub_external(
            '0x9185cf46bc8ef7d6a2906b5db87c43611f40bc47bccd14d5606d89b5e35ca620',
            '0x8e819e9b4fcaf230255c4273059121d96e45da765348d66fabbb3fa0304a68dd',
        );
        expect(c).to.be.eq(
            '0x030430ab6cc405a67d3428eab2eb2187b0fae1d169843e65b4b24a15b3123d43'.toLocaleLowerCase(),
        );
        // We will randomly sample much larger numbs for more cases
        for (let i = 0; i < 10; i++) {
            // 256 bytes is the target big numb rsa size
            let a = utils.randomBytes(32);
            let b = utils.randomBytes(32);
            // We don't want underflow reverts
            if (utils.bigNumberify(a).lt(utils.bigNumberify(b))) {
                [a, b] = [b, a];
            }
            verifier.big_sub_external(a, b).then((c: any) => {
                expect(c).to.be.eq(
                    utils
                        .bigNumberify(a)
                        .sub(utils.bigNumberify(b))
                        .toHexString(),
                );
            });
        }
    });

    it('Should validate a correct hash to prime', async () => {
        await verifier.check_hash_to_prime(
            '0xB8BA422C143FC4091BE420A7702CDD814B6D7DE7BBA7F19EC4F546B97691194F',
            '0x56F6638C8E6465BFF83B70B88EDEB590E8AC7D18AC03E9D6C3D4F0D6DD0D0D29422F9D8F6D38858A63498E76F6D8B45B05AB69C105E24FC60F6E4FF9184D63AABD3BBEE3C041251EBE2F89C9AE936643F51EB62C76BF5F07CF9A45081073AF0145C96472F3CF253C6E5D83E997455235B4D2EA36CEF284FC2B59A17472D479ECA7FE72E53D3FA7029110AD7536980CCBACF64DD819B6848A4A4A16D5B4CFF747CD6F61EA7F3055AEA2A72B2AED710113A00C53A85902752687795E96B3D3953AE0D8F067382242FFD789246D0B79FA2B6018B2E9B8642D2158659DACE5FB57AE1087C204B142137C9E5F5DB3694CFBA0393E641D10640DD12E313E11F00A5ED0',
            '0x84e07693b3c6f6ae1e9b128abebf2e743b5f68bf24ab3ff27947221b47f490a3',
        );
    });

    it('Should validate a correct proof', async () => {
        const result = await (await verifier.verify_vdf_proof_gas(
            // input random / g
            '0x194B4753D92469B4EC1C01AD36C38D53C75F32701B148D215D49A292284D9046',
            // y
            '0x30D364E0C51908B61E5CCBD924A27D1CE16B286038F5FD2052AAA9D29E146A3BE2261E64F487A063F9152DFE67259BF6B083AA08620FBD96D21F06AAF22BA3BF3CAB3AC4C95C3C10D440DFEF38DA3231E25FAEA7094BEA2E6ED28FA7C6EB16B88E5B16E17B876ABA9A397A18D01AA8A53144E0A47F442AE5A2074420CF5CF2C8C79343FF1ABF17F0AB24D77C428923781CDD08320DC269A2D9817F057BC0424A81C9CF0342D65895767541DC4F658074B78E48AB9B62B4AF6C676B1A0B6B197703838D99E41502010FD7A60D7E66447CF2EFC88F9ED57A3CC048860713D11DBE260DDF8A8BCB397B06C898CA90871481AB1713439021D78B19E4B0D26DDB88DC',
            // pi
            '0x4EA5F2F9B56E43F79F52199F6E01195E48844600D4CEA0215B78982702091462B70D9601D6F5EBF78EF2EDE8814F8F3D5C36C718559F658ADE8B3BBF37E7D2FA23A96F2E7F9EACC70C8C3678ED7C36E419F58A1E77EDA6BCF6A811D5CF021E24870FDD027351A93861BD69AA12CEF59AAF4CAD912733E5D84F292BF062E2530F24602A314FA7CE20D77843FD7CE02F43A721EA7245395CB25F99980DF6A64CCD2B2FF92CC96F93FEE9BB2F7FC1F0F11E39F3706CFF772008129A9601421BBB6F4FED13AB2F7CC401959C5EA6AC7E47B230C66E1730521AD8BDF68C9822F4970925A42A74797EED58CC845FD77DB63517368011982D424DABC07D211890D41124',
            // iterations / t
            20000000000,
            // prime / l
            '0xBD63097802DC383264E04E795B649A4B50F10B7D9A6023EAC74B6DA9D49CB42D',
        )).wait();
        console.log("The verifier took this much gas:");
        console.log(result.gasUsed.toNumber());
    });
});
