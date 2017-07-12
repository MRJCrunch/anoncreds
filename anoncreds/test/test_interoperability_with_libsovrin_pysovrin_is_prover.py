import socket
import json
import asyncio
import logging

from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.repo.attributes_repo import AttributeRepoInMemory
from anoncreds.protocol.repo.public_repo import PublicRepoInMemory
from anoncreds.protocol.types import ID, ProofRequest
from anoncreds.protocol.wallet.issuer_wallet import IssuerWalletInMemory
from anoncreds.test.conftest import GVT, primes1
from anoncreds.protocol.prover import Prover
from anoncreds.protocol.wallet.prover_wallet import ProverWalletInMemory

logging.basicConfig(format=u'%(filename)s[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s',
                    level=logging.DEBUG)

loop = asyncio.get_event_loop()
global_dict = {}
ip = '127.0.0.1'
port = 1234
chunk_size = 102400


def main():
    sock = socket.socket()
    sock.bind((ip, port))
    sock.listen(1)
    logging.debug('Listening')
    conn, _ = sock.accept()
    logging.debug('Connected')

    while True:
        data = json.loads(conn.recv(chunk_size).decode("utf-8"))
        logging.debug('received data: {}'.format(data))
        if ('type' in data) & (data['type'] == 'get_claim_def'):
            logging.debug('get_claim_def -> start')
            future = asyncio.ensure_future(init(primes1(), conn))
            loop.run_until_complete(future)
            logging.debug('get_claim_def -> done')
        if ('type' in data) & (data['type'] == 'get_proof'):
            logging.debug('get_proof -> start')
            future = asyncio.ensure_future(create_proof(conn, data['data']))
            loop.run_until_complete(future)
            logging.debug('get_proof -> done')
        if (('type' in data) & (data['type'] == 'close')) | (not data):
            break

    sock.close()

async def init(primes, conn):
    # 1. Init entities
    public_repo = PublicRepoInMemory()
    attr_repo = AttributeRepoInMemory()
    issuer = Issuer(IssuerWalletInMemory('issuer1', public_repo), attr_repo)

    # 2. Create a Schema
    schema = await issuer.genSchema('GVT', '1.0', GVT.attribNames())
    schema_id = ID(schema.getKey())

    # 3. Create keys for the Schema
    await issuer.genKeys(schema_id, **primes)

    # 4. Issue accumulator
    await issuer.issueAccumulator(schemaId=schema_id, iA='110', L=5)

    # 5. set attributes for user1
    prover_id = 'BzfFCYk'
    attributes = GVT.attribs(name='Alex', age=28, height=175, sex='male')
    attr_repo.addAttributes(schema.getKey(), prover_id, attributes)

    # 6. request Claims
    prover = Prover(ProverWalletInMemory(prover_id, public_repo))
    claims_req = await prover.createClaimRequest(schema_id, reqNonRevoc=False)
    (claim_signature, claim_attributes) = await issuer.issueClaim(schema_id, claims_req)

    await prover.processClaim(schema_id, claim_attributes, claim_signature)

    global global_dict
    global_dict = {
        'prover': prover
    }

    public_key = await issuer.wallet.getPublicKey(schema_id)

    conn.send(json.dumps({
        'primary': public_key.to_str_dict(),
        'revocation': None
    }).encode())


async def create_proof(conn, proof_request):
    proof_request = ProofRequest.from_str_dict(proof_request)
    proof = await global_dict['prover'].presentProof(proof_request)

    conn.send(json.dumps(proof.to_str_dict()).encode())

if __name__ == '__main__':
    main()
