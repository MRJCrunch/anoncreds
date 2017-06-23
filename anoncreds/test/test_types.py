import pytest

from anoncreds.protocol.types import PublicKey, Schema, Claims, \
    ProofInput, PredicateGE, FullProof, \
    SchemaKey, ClaimRequest, Proof, AttributeInfo, ProofInfo, AggregatedProof, RequestedProof, PrimaryProof, \
    PrimaryEqualProof, PrimaryPredicateGEProof, ID, AttributeValues
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


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
def testRequestClaimsFromToDict(claimsRequestProver1Gvt):
    assert claimsRequestProver1Gvt == ClaimRequest.fromStrDict(
        claimsRequestProver1Gvt.toStrDict())


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
def testClaimsFromToDict(claimsProver1Gvt):
    assert claimsProver1Gvt == Claims.fromStrDict(claimsProver1Gvt.toStrDict())


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
def testClaimsFromToDictPrimaryOnly(claimsProver1Gvt):
    claims = Claims(primaryClaim=claimsProver1Gvt.primaryClaim)
    assert claims == Claims.fromStrDict(claims.toStrDict())


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testAggregatedProofFromToDict(prover1, nonce, claimsProver1Gvt):
    proofInput = ProofInput(nonce=nonce,
                            revealedAttrs={'attr_uuid': AttributeInfo(name='name')},
                            predicates={'predicate_uuid': PredicateGE('age', 18)})

    proof = await prover1.presentProof(proofInput)

    assert proof.aggregatedProof == AggregatedProof.fromStrDict(proof.aggregatedProof.toStrDict())


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testRequestedProofFromToDict(prover1, nonce, claimsProver1Gvt):
    proofInput = ProofInput(nonce=nonce,
                            revealedAttrs={'attr_uuid': AttributeInfo(name='name')},
                            predicates={'predicate_uuid': PredicateGE('age', 18)})

    proof = await prover1.presentProof(proofInput)

    assert proof.requestedProof == RequestedProof.fromStrDict(proof.requestedProof.toStrDict())


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testClaimProofFromToDict(prover1, nonce, claimsProver1Gvt):
    proofInput = ProofInput(nonce=nonce,
                            revealedAttrs={'attr_uuid': AttributeInfo(name='name')},
                            predicates={'predicate_uuid': PredicateGE('age', 18)})

    proof = await prover1.presentProof(proofInput)

    assert proof == FullProof.fromStrDict(proof.toStrDict())


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testClaimProofFromToDictPrimaryOnly(prover1, nonce, claimsProver1Gvt, schemaGvt):
    proofInput = ProofInput(nonce=nonce,
                            revealedAttrs={'attr_uuid': AttributeInfo(name='name')},
                            predicates={'predicate_uuid': PredicateGE('age', 18)})

    proof = await prover1.presentProof(proofInput)

    proofInfo = proof.proofs[str(schemaGvt.seqId)]
    proofs = {schemaGvt.seqId: ProofInfo(Proof(primaryProof=proofInfo.proof.primaryProof),
                                            claim_def_seq_no=proofInfo.claim_def_seq_no,
                                            schema_seq_no=proofInfo.schema_seq_no)}
    proof = proof._replace(proofs=proofs)
    assert proof == FullProof.fromStrDict(proof.toStrDict())


def testProofInputFromToDict():
    proofInput = ProofInput(nonce=1,
                            revealedAttrs={'attr_uuid1': AttributeInfo(name='name'),
                                           'attr_uuid2': AttributeInfo(name='age')},
                            predicates={'predicate_uuid1': PredicateGE('age', 18),
                                        'predicate_uuid2': PredicateGE('age', 25)})

    assert proofInput == ProofInput.fromStrDict(proofInput.toStrDict())


def test_proof_input_from_to_dict():
    proof_input = ProofInput(nonce=1,
                             revealedAttrs={'attr_uuid': AttributeInfo(name='name')},
                             predicates={'predicate_uuid': PredicateGE('age', 18)})

    proof_input_serialized = {
        'nonce': '1',
        'revealedAttrs': {'attr_uuid': {'name': 'name', 'schema_seq_no': None}},
        'predicates': {'predicate_uuid': {'type': 'ge', 'value': 18, 'attrName': 'age'}}
    }
    assert proof_input.to_str_dict() == proof_input_serialized
    assert proof_input == ProofInput.from_str_dict(proof_input_serialized)
    assert proof_input == ProofInput.from_str_dict(proof_input.to_str_dict())



@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def test_requested_proof_from_to_dict(prover1, nonce, claimsProver1Gvt):
    proofInput = ProofInput(nonce=nonce,
                            revealedAttrs={'attr_uuid': AttributeInfo(name='name')},
                            predicates={'predicate_uuid': PredicateGE('age', 18)})

    proof = await prover1.presentProof(proofInput)

    requested_proof_serialized = {
        'revealed_attrs': {'attr_uuid': ['1', 'Alex', '1139481716457488690172217916278103335']},
        'predicates': {'predicate_uuid': '1'},
        'self_attested_attrs': {},
        'unrevealed_attrs': {}
    }

    assert proof.requestedProof.to_str_dict() == requested_proof_serialized
    assert proof.requestedProof == RequestedProof.from_str_dict(requested_proof_serialized)
    assert proof.requestedProof == RequestedProof.from_str_dict(proof.requestedProof.to_str_dict())


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def test_attribute_values_from_to_dict():

    attr_values = AttributeValues(raw='Alex', encoded=cmod.integer(11))

    attr_values_serialized = ['Alex', '11']

    assert attr_values.to_str_dict() == attr_values_serialized
    assert attr_values == AttributeValues.from_str_dict(attr_values_serialized)
    assert attr_values == AttributeValues.from_str_dict(attr_values.to_str_dict())


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def test_aggregated_proof_from_to_dict(prover1, nonce, claimsProver1Gvt):
    aggregated_proof = AggregatedProof(1, [cmod.integer(111), cmod.integer(32321), cmod.integer(323)])

    aggregated_proof_serialized = {
        'cHash': '1',
        'CList': [[111], [126, 65], [1, 67]]
    }

    assert aggregated_proof.to_str_dict() == aggregated_proof_serialized
    assert aggregated_proof == AggregatedProof.from_str_dict(aggregated_proof_serialized)
    assert aggregated_proof == AggregatedProof.from_str_dict(aggregated_proof.to_str_dict())


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def test_equal_proof_from_to_dict():
    n = cmod.integer(12345)

    eqProof = PrimaryEqualProof(e=cmod.integer(1), v=cmod.integer(11), m={'name': cmod.integer(12)},
                                m1=cmod.integer(12), m2=cmod.integer(32), Aprime=cmod.integer(32) % n,
                                revealedAttrs={'name': cmod.integer(35)})

    proof_serialized = {
        'Aprime': '32',
        'e': '1',
        'm': {'name': '12'},
        'm1': '12',
        'm2': '32',
        'v': '11',
        'revealedAttrs': {'name': '35'}
    }

    assert eqProof.to_str_dict() == proof_serialized
    assert eqProof == PrimaryEqualProof.from_str_dict(proof_serialized, n)
    assert eqProof == PrimaryEqualProof.from_str_dict(eqProof.to_str_dict(), n)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def test_ge_proof_from_to_dict():
    n = cmod.integer(12345)

    predicate = PredicateGE(attrName='age', value=18)
    geProof = PrimaryPredicateGEProof(alpha=cmod.integer(1), mj=cmod.integer(12), r={'1': cmod.integer(13)},
                                      u={'1': cmod.integer(42)}, T={'1': cmod.integer(21) % n}, predicate=predicate)

    proof_serialized = {
        'alpha': '1',
        'mj': '12',
        'T': {'1': '21'},
        'r': {'1': '13'},
        'u': {'1': '42'},
        'predicate': {
            'type': 'ge',
            'attrName': 'age',
            'value': 18
        }
    }

    assert geProof.to_str_dict() == proof_serialized
    assert geProof == PrimaryPredicateGEProof.from_str_dict(proof_serialized, n)
    assert geProof == PrimaryPredicateGEProof.from_str_dict(geProof.to_str_dict(), n)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def test_primary_proof_from_to_dict():
    n = cmod.integer(12345)

    eqProof = PrimaryEqualProof(e=cmod.integer(1), v=cmod.integer(11), m={'name': cmod.integer(12)},
                                m1=cmod.integer(12), m2=cmod.integer(32), Aprime=cmod.integer(32) % n,
                                revealedAttrs={'name': cmod.integer(35)})

    predicate = PredicateGE(attrName='age', value=18)
    geProof = PrimaryPredicateGEProof(alpha=cmod.integer(1), mj=cmod.integer(12), r={'1': cmod.integer(13)},
                                      u={'1': cmod.integer(42)}, T={'1': cmod.integer(21) % n}, predicate=predicate)
    primaryProof = PrimaryProof(eqProof=eqProof, geProofs=[geProof])

    proof_serialized = {
        'eqProof': {
            'Aprime': '32',
            'e': '1',
            'm': {'name': '12'},
            'm1': '12',
            'm2': '32',
            'v': '11',
            'revealedAttrs': {'name': '35'}
        },
        'geProofs': [
            {
                'alpha': '1',
                'mj': '12',
                'T': {'1': '21'},
                'r': {'1': '13'},
                'u': {'1': '42'},
                'predicate': {
                    'type': 'ge',
                    'attrName': 'age',
                    'value': 18
                }
            }
        ]
    }

    assert primaryProof.to_str_dict() == proof_serialized
    assert primaryProof == PrimaryProof.from_str_dict(proof_serialized, n)
    assert primaryProof == PrimaryProof.from_str_dict(primaryProof.to_str_dict(), n)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def test_proof_info_from_to_dict():
    n = cmod.integer(12345)

    eqProof = PrimaryEqualProof(e=cmod.integer(1), v=cmod.integer(11), m={'name': cmod.integer(12)},
                                m1=cmod.integer(12), m2=cmod.integer(32), Aprime=cmod.integer(32) % n,
                                revealedAttrs={'name': cmod.integer(35)})

    predicate = PredicateGE(attrName='age', value=18)
    geProof = PrimaryPredicateGEProof(alpha=cmod.integer(1), mj=cmod.integer(12), r={'1': cmod.integer(13)},
                                      u={'1': cmod.integer(42)}, T={'1': cmod.integer(21) % n}, predicate=predicate)
    primaryProof = PrimaryProof(eqProof=eqProof, geProofs=[geProof])
    proofInfo = Proof(primaryProof=primaryProof)
    proof = ProofInfo(claim_def_seq_no=1, schema_seq_no=1, proof=proofInfo)

    proof_serialized = {
        'claim_def_seq_no': 1,
        'schema_seq_no': 1,
        'proof': {
            'primaryProof': {
                'eqProof': {
                    'Aprime': '32',
                    'e': '1',
                    'm': {'name': '12'},
                    'm1': '12',
                    'm2': '32',
                    'v': '11',
                    'revealedAttrs': {'name': '35'}
                },
                'geProofs': [
                    {
                        'alpha': '1',
                        'mj': '12',
                        'T': {'1': '21'},
                        'r': {'1': '13'},
                        'u': {'1': '42'},
                        'predicate': {
                            'type': 'ge',
                            'attrName': 'age',
                            'value': 18
                        }
                    }
                ]
            }
        }
    }

    assert proof.to_str_dict() == proof_serialized
    assert proof == ProofInfo.from_str_dict(proof_serialized, n)
    assert proof == ProofInfo.from_str_dict(proof.to_str_dict(), n)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def test_proof_from_to_dict(prover1, nonce, claimsProver1Gvt, schemaGvt):
    n = (await prover1.wallet.getPublicKey(ID(schemaId=schemaGvt.seqId))).N
    proofInput = ProofInput(nonce=nonce,
                            revealedAttrs={'attr_uuid': AttributeInfo(name='name')},
                            predicates={'predicate_uuid': PredicateGE('age', 18)})

    proof = await prover1.presentProof(proofInput)

    proofInfo = proof.proofs[str(schemaGvt.seqId)]
    proof = ProofInfo(Proof(primaryProof=proofInfo.proof.primaryProof),
                      claim_def_seq_no=proofInfo.claim_def_seq_no,
                      schema_seq_no=proofInfo.schema_seq_no)

    assert proof == ProofInfo.from_str_dict(proof.to_str_dict(), n)