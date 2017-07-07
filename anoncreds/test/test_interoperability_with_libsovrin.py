import socket
import json
import asyncio
from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.prover import Prover
from anoncreds.protocol.repo.attributes_repo import AttributeRepoInMemory
from anoncreds.protocol.repo.public_repo import PublicRepoInMemory
from anoncreds.protocol.types import ProofInput, PredicateGE, \
    ID, ClaimRequest
from anoncreds.protocol.verifier import Verifier
from anoncreds.protocol.wallet.issuer_wallet import IssuerWalletInMemory
from anoncreds.protocol.wallet.prover_wallet import ProverWalletInMemory
from anoncreds.protocol.wallet.wallet import WalletInMemory
from anoncreds.test.conftest import GVT, XYZCorp, primes1


from anoncreds.protocol.utils import toDictWithStrValues, \
    fromDictWithStrValues, deserializeFromStr, encodeAttr, crypto_int_to_str, to_crypto_int
loop = asyncio.get_event_loop()


def main():
    sock = socket.socket()
    sock.bind(('127.0.0.1', 1234))
    sock.listen(1)
    print('Listen')
    conn, addr = sock.accept()
    print('Connected')

    while True:
        data = json.loads(conn.recv(1024).decode("utf-8"))
        print(data)
        if ('type' in data) & (data['type'] == 'issue'):
            print('in issuer')
            b = asyncio.ensure_future(issuer_init(primes1(), conn, data['data']['blinded_ms']))
            loop.run_until_complete(b)
            print(data['data'])
            print('sent an answer')
        if (('type' in data) & (data['type'] == 'close')) | (not data):
            break

    sock.close()

async def issuer_init(primes, conn, claim_request):
    # 1. Init entities
    publicRepo = PublicRepoInMemory()
    attrRepo = AttributeRepoInMemory()
    issuer = Issuer(IssuerWalletInMemory('issuer1', publicRepo), attrRepo)

    # 2. Create a Schema
    schema = await issuer.genSchema('GVT', '1.0', GVT.attribNames())
    schemaId = ID(schema.getKey())

    # 3. Create keys for the Schema
    await issuer.genKeys(schemaId, **primes)

    # 4. Issue accumulator
    await issuer.issueAccumulator(schemaId=schemaId, iA='110', L=5)

    # 4. set attributes for user1
    userId = 'BzfFCYk'
    attrs = GVT.attribs(name='Alex', age=28, height=175, sex='male')
    attrRepo.addAttributes(schema.getKey(), userId, attrs)

    public_key = await issuer.wallet.getPublicKey(schemaId)
    claim_request = ClaimRequest.from_str_dict(claim_request, public_key.N)
    print(claim_request)
    claims = await issuer.issueClaim(schemaId, claim_request)
    claims = {
           'primaryClaim': {
                'm2': str(crypto_int_to_str(claims.primaryClaim.m2)),
                'a': str(crypto_int_to_str(claims.primaryClaim.A)),
                'e': str(claims.primaryClaim.e),
                'v': str(claims.primaryClaim.v)
            },
           'nonRevocClaim': None
        }

    print(claims)
    conn.send(json.dumps(claims).encode())

if __name__ == '__main__':
    main()
