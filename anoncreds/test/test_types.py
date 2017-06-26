import pytest

from anoncreds.protocol.types import PublicKey, Schema, Claims, \
    ProofInput, PredicateGE, FullProof, \
    SchemaKey, ClaimRequest, Proof, PrimaryClaim, AttributeValues
from anoncreds.protocol.utils import toDictWithStrValues, fromDictWithStrValues
from config.config import cmod


def testSchemaKeyFromToDict():
    schemaKey = SchemaKey(name='schemaName', version='1.0',
                            issuerId='issuer1')
    assert schemaKey == SchemaKey.fromStrDict(
        schemaKey.toStrDict())


def testSchemaFromToDict():
    schema = Schema(name='schemaName',
                    version='1.0',
                    attrNames=['attr1', 'attr2', 'attr3'],
                    issuerId='issuer1')
    assert schema == Schema.fromStrDict(schema.toStrDict())


def testPKFromToDict():
    pk = PublicKey(N=cmod.integer(11),
                   Rms=cmod.integer(12),
                   Rctxt=cmod.integer(13),
                   R={'a': cmod.integer(1), 'b': cmod.integer(2)},
                   S=cmod.integer(14),
                   Z=cmod.integer(15))

    assert pk == PublicKey.fromStrDict(pk.toStrDict())


def test_pk_from_to_dict():
    pk = PublicKey(N=cmod.integer(12345),
                   Rms=cmod.integer(12) % cmod.integer(12345),
                   Rctxt=cmod.integer(13) % cmod.integer(12345),
                   R={'name': cmod.integer(1) % cmod.integer(12345), 'age': cmod.integer(2) % cmod.integer(12345)},
                   S=cmod.integer(14) % cmod.integer(12345),
                   Z=cmod.integer(15) % cmod.integer(12345))

    pk_serialized = {
        'n': '12345',
        'rms': '12',
        'rctxt': '13',
        'r': {
            'name': '1',
            'age': '2'
        },
        's': '14',
        'z': '15',
    }

    assert pk.to_str_dict() == pk_serialized
    assert pk == PublicKey.from_str_dict(pk_serialized)


def test_claim_request_from_to_dict():
    n = cmod.integer(12345)
    u = cmod.integer(12) % n
    prover_did = '123456789'
    claim_request = ClaimRequest(userId=prover_did, U=u, Ur=None)

    claim_request_serialized = {
        'prover_did': '123456789',
        'u': '12',
        'ur': None
    }

    assert claim_request.to_str_dict() == claim_request_serialized
    assert claim_request == ClaimRequest.from_str_dict(claim_request_serialized, n)


def test_claim_from_to_dict():
    n = cmod.integer(111111111)
    m2 = cmod.integer(123)
    a = cmod.integer(456) % n
    e = 567
    v = cmod.integer(999)

    claim = PrimaryClaim(m2, a, e, v)
    claim_serialized = {
        'm2': '123',
        'a': '456',
        'e': '567',
        'v': '999'
    }

    assert claim_serialized == claim.to_str_dict()
    assert claim == PrimaryClaim.from_str_dict(claim_serialized, n)

@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
def testRequestClaimsFromToDict(claimsRequestProver1Gvt):
    assert claimsRequestProver1Gvt == ClaimRequest.fromStrDict(
        claimsRequestProver1Gvt.toStrDict())


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
def testClaimsFromToDict(claimSignatureProver1Gvt):
    assert claimSignatureProver1Gvt == Claims.fromStrDict(claimSignatureProver1Gvt.toStrDict())


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
def testClaimsFromToDictPrimaryOnly(claimSignatureProver1Gvt):
    claims = Claims(primaryClaim=claimSignatureProver1Gvt.primaryClaim)
    assert claims == Claims.fromStrDict(claims.toStrDict())


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testClaimProofFromToDict(prover1, nonce, claimSignatureProver1Gvt):
    proofInput = ProofInput(['name'], [PredicateGE('age', 18)])
    proof, _ = await prover1.presentProof(proofInput, nonce)
    assert proof == FullProof.fromStrDict(proof.toStrDict())


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testClaimProofFromToDictPrimaryOnly(prover1, nonce, claimSignatureProver1Gvt):
    proofInput = ProofInput(['name'], [PredicateGE('age', 18)])
    proof, _ = await prover1.presentProof(proofInput, nonce)

    proofs = [Proof(primaryProof=proof.proofs[0].primaryProof)]
    proof = proof._replace(proofs=proofs)
    assert proof == FullProof.fromStrDict(proof.toStrDict())


def testProofInputFromToDict():
    proofInput = ProofInput(['name', 'age'],
                            [PredicateGE('age', 18), PredicateGE('age', 25)])
    assert proofInput == ProofInput.fromStrDict(proofInput.toStrDict())


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testRevealedAttrsFromToDict(prover1, nonce, claimSignatureProver1Gvt):
    proofInput = ProofInput(['name'], [PredicateGE('age', 18)])
    _, revealedAttrs = await prover1.presentProof(proofInput, nonce)
    assert revealedAttrs == fromDictWithStrValues(
        toDictWithStrValues(revealedAttrs))


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def test_attribute_values_from_to_dict():

    attr_values = AttributeValues(raw='Alex', encoded=cmod.integer(11))

    attr_values_serialized = ['Alex', '11']

    assert attr_values.to_str_dict() == attr_values_serialized
    assert attr_values == AttributeValues.from_str_dict(attr_values_serialized)
    assert attr_values == AttributeValues.from_str_dict(attr_values.to_str_dict())
