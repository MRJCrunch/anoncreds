import socket
import json
import asyncio
import logging

from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.prover import Prover
from anoncreds.protocol.repo.attributes_repo import AttributeRepoInMemory
from anoncreds.protocol.repo.public_repo import PublicRepoInMemory
from anoncreds.protocol.types import ProofInput, PredicateGE, \
    ID, AttributeInfo, ProofRequest, FullProof, PublicKey
from anoncreds.protocol.verifier import Verifier
from anoncreds.protocol.wallet.issuer_wallet import IssuerWalletInMemory
from anoncreds.protocol.wallet.prover_wallet import ProverWalletInMemory
from anoncreds.protocol.wallet.wallet import WalletInMemory
from anoncreds.test.conftest import GVT, XYZCorp

logging.basicConfig(format=u'%(filename)s[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s',
                    level=logging.DEBUG)

loop = asyncio.get_event_loop()
global_dict = {
    'verifier': '',
    'proof_request': '',
    'public_key': ''
}
ip = '127.0.0.1'
port = 1234


def main():
    sock = socket.socket()
    sock.bind((ip, port))
    sock.listen(1)
    logging.debug('Listening')
    conn, _ = sock.accept()
    logging.debug('Connected')

    while True:
        data = json.loads(conn.recv(102400).decode("utf-8"))
        logging.debug('received data: {}'.format(data))
        if ('type' in data) & (data['type'] == 'receive_claim_def'):
            logging.debug('receive_claim_def -> start')
            global global_dict
            global_dict['public_key'] = PublicKey.from_str_dict(data['data']['data']['primary'])
            logging.debug('receive_claim_def -> done')
        if ('type' in data) & (data['type'] == 'get_proof_request'):
            logging.debug('get_proof_request -> start')
            create_proof_request(conn)
            logging.debug('get_proof_request -> done')
        if ('type' in data) & (data['type'] == 'check_proof'):
            logging.debug('check_proof -> start')
            check_proof = asyncio.ensure_future(verify(data['data'], conn))
            loop.run_until_complete(check_proof)
            logging.debug('check_proof -> done')
        if (('type' in data) & (data['type'] == 'close')) | (not data):
            break

    sock.close()


def create_proof_request(conn):
    verifier = Verifier(WalletInMemory('verifier1', PublicRepoInMemory()))

    proof_request = ProofRequest(
        name='Test_proof', version='1.0',
        nonce=verifier.generateNonce(),
        verifiableAttributes={'attr_uuid': AttributeInfo('name')},
        predicates={'predicate_uuid': PredicateGE('age', 18)})

    global global_dict
    global_dict['verifier'] = verifier
    global_dict['proof_request'] = proof_request

    conn.send(json.dumps(proof_request.to_str_dict()).encode())

async def verify(proof, conn):
    proof = FullProof.from_str_dict(proof, global_dict['public_key'].N)
    print('proof: {}'.format(proof))
    assert proof.requestedProof.revealed_attrs['attr_uuid'][1] == 'Alex'
    valid = await global_dict['verifier'].verify(global_dict['proof_request'], proof)
    print('valid: {}'.format(valid))
    conn.send(json.dumps(valid).encode())

if __name__ == '__main__':
    main()
