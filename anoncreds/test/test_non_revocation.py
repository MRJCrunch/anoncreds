import pytest

from anoncreds.protocol.types import ProofInput
from anoncreds.protocol.utils import groupIdentityG1
from anoncreds.test.conftest import presentProofAndVerify


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testIssueRevocationCredential(claimSignatureProver1Gvt, issuerGvt,
                                        schemaGvtId):
    nonRevocClaimGvtProver1 = claimSignatureProver1Gvt.nonRevocClaim
    acc = await issuerGvt.wallet.getAccumulator(schemaGvtId)
    tails = await issuerGvt.wallet.getTails(schemaGvtId)
    assert nonRevocClaimGvtProver1
    assert nonRevocClaimGvtProver1.witness
    assert nonRevocClaimGvtProver1.witness.V
    assert nonRevocClaimGvtProver1.i == 1
    assert nonRevocClaimGvtProver1.witness.gi == tails[1]

    assert acc.V
    assert acc.acc != 1

    assert nonRevocClaimGvtProver1.witness.V == acc.V


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testRevoce(claimSignatureProver1Gvt, issuerGvt, schemaGvtId):
    await issuerGvt.revoke(schemaGvtId, 1)
    newAcc = await issuerGvt.wallet.getAccumulator(schemaGvtId)
    assert not newAcc.V
    assert newAcc.acc == groupIdentityG1()


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testUpdateWitnessNotChangedIfInSync(claimSignatureProver1Gvt, schemaGvtId,
                                              prover1):
    nonRevocClaimGvtProver1 = claimSignatureProver1Gvt.nonRevocClaim
    acc = await prover1.wallet.getAccumulator(schemaGvtId)

    # not changed as in sync
    oldOmega = nonRevocClaimGvtProver1.witness.omega

    c2 = await prover1._nonRevocProofBuilder.updateNonRevocationClaim(
        schemaGvtId.schemaKey,
        nonRevocClaimGvtProver1)
    assert c2.witness.V == acc.V
    assert oldOmega == c2.witness.omega


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testUpdateWitnessChangedIfOutOfSync(claimSignatureProver1Gvt, issuerGvt,
                                              schemaGvtId, prover1):
    nonRevocClaimGvtProver1 = claimSignatureProver1Gvt.nonRevocClaim
    acc = await issuerGvt.wallet.getAccumulator(schemaGvtId)

    # not in sync
    acc.V.add(3)
    assert nonRevocClaimGvtProver1.witness.V != acc.V

    # witness is updated
    oldOmega = nonRevocClaimGvtProver1.witness.omega
    c2 = await prover1._nonRevocProofBuilder.updateNonRevocationClaim(
        schemaGvtId.schemaKey,
        nonRevocClaimGvtProver1)
    assert c2.witness.V == acc.V
    assert oldOmega != c2.witness.omega


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testUpdateRevocedWitness(claimSignatureProver1Gvt, issuerGvt, schemaGvtId,
                                   prover1):
    nonRevocClaimGvtProver1 = claimSignatureProver1Gvt.nonRevocClaim
    await issuerGvt.revoke(schemaGvtId, 1)
    with pytest.raises(ValueError):
        await prover1._nonRevocProofBuilder.updateNonRevocationClaim(
            schemaGvtId.schemaKey, nonRevocClaimGvtProver1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testInitNonRevocClaim(schemaGvtId, prover1, issuerGvt,
                                attrsProver1Gvt, keysGvt, issueAccumulatorGvt):
    claimsReq = await prover1.createClaimRequest(schemaGvtId)
    (signature, claims) = await issuerGvt.issueClaim(schemaGvtId, claimsReq)

    oldV = signature.nonRevocClaim.v
    await prover1.processClaim(schemaGvtId, claims, signature)
    newC2 = (await prover1.wallet.getClaimSignature(schemaGvtId)).nonRevocClaim
    vrPrime = (
        await prover1.wallet.getNonRevocClaimInitData(schemaGvtId)).vPrime

    assert oldV + vrPrime == newC2.v


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testCAndTauList(claimSignatureProver1Gvt, schemaGvtId, prover1):
    nonRevocClaimGvtProver1 = claimSignatureProver1Gvt.nonRevocClaim
    proofRevBuilder = prover1._nonRevocProofBuilder
    assert await proofRevBuilder.testProof(schemaGvtId.schemaKey,
                                           nonRevocClaimGvtProver1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testRevocedWithUpdateWitness(schemaGvtId, issuerGvt, prover1,
                                       verifier, claimSignatureProver1Gvt):
    await issuerGvt.revoke(schemaGvtId, 1)

    proofInput = ProofInput(['name'], [])
    with pytest.raises(ValueError):
        await presentProofAndVerify(verifier, proofInput, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testRevocedWithoutUpdateWitness(schemaGvtId, issuerGvt, prover1,
                                          verifier, claimSignatureProver1Gvt):
    proofInput = ProofInput(['name'], [])
    nonce = verifier.generateNonce()
    proof, revealedAttrs = await prover1.presentProof(proofInput, nonce)

    await issuerGvt.revoke(schemaGvtId, 1)

    return await verifier.verify(proofInput, proof, revealedAttrs, nonce)
