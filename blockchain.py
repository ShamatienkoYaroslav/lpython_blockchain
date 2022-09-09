from functools import reduce
from http.client import responses
from logging import exception
import pickle
import os.path as path

import requests

from utility.hash_util import hash_block
from utility.verification import Verification
from utility.dirs import create_dirs
from block import Block
from transaction import Transaction
from wallet import Wallet

MINING_REWARD = 10


class Blockchain:
    def __init__(self, public_key, node_id):
        genesis_block = Block(index=0, previous_hash='',
                              transactions=[], proof=100)
        self.chain = [genesis_block]
        self.public_key = public_key
        self.node_id = node_id
        self.data_path = path.join('data/blockchains/', 'blockchain-{}.p'.format(
            self.node_id))
        self.resolve_conflicts = False
        self.__open_transactions = []
        self.__peer_nodes = set()
        create_dirs('data/blockchains')
        self.load_data()

    @property
    def chain(self):
        return self.__chain[:]

    @chain.setter
    def chain(self, value):
        self.__chain = value

    def get_chain(self):
        return self.__chain[:]

    def get_open_transactions(self):
        return self.__open_transactions[:]

    def load_data(self):
        try:
            with open(self.data_path, mode='rb') as f:
                file_content = pickle.loads(f.read())

                self.__chain = file_content['chain']
                self.__open_transactions = file_content['ot']
                self.__peer_nodes = file_content['peer_nodes']
        except IOError:
            pass

    def save_data(self):
        try:
            with open(self.data_path, mode='wb') as f:
                save_data = {
                    'chain': self.__chain,
                    'ot': self.__open_transactions,
                    'peer_nodes': self.__peer_nodes
                }
                f.write(pickle.dumps(save_data))
        except IOError:
            print('Saving failed!')

    def proof_of_work(self):
        last_block = self.__chain[-1]
        last_hash = hash_block(last_block)
        proof = 0
        while not Verification.valid_proof(self.__open_transactions, last_hash, proof):
            proof += 1
        return proof

    def get_balance(self, sender=None):
        if sender == None:
            if self.public_key == None:
                return None
            participant = self.public_key
        else:
            participant = sender

        tx_sender = [[tx.amount for tx in block.transactions if tx.sender ==
                      participant] for block in self.__chain]
        tx_sender_open = [
            tx.amount for tx in self.__open_transactions if tx.sender == participant]
        tx_sender.append(tx_sender_open)
        amount_send = reduce(lambda tx_sum, tx_amt: tx_sum + sum(tx_amt)
                             if len(tx_amt) > 0 else tx_sum + 0, tx_sender, 0)
        tx_recipient = [[tx.amount for tx in block.transactions if tx.recipient ==
                         participant] for block in self.__chain]
        amount_received = reduce(lambda tx_sum, tx_amt: tx_sum + sum(tx_amt)
                                 if len(tx_amt) > 0 else tx_sum + 0, tx_recipient, 0)
        return amount_received - amount_send

    def get_last_blockchain_value(self):
        if len(self.__chain) < 1:
            return None
        return self.__chain[-1]

    def add_transaction(self, recipient, sender, signature, amount=1.0, is_receiving=False):
        if self.public_key == None:
            return False

        transaction = Transaction(
            sender=sender, recipient=recipient, signature=signature, amount=amount)
        if Verification.verify_transaction(transaction, self.get_balance):
            self.__open_transactions.append(transaction)
            self.save_data()
            if not is_receiving:
                for node in self.__peer_nodes:
                    url = 'http://{}/broadcast_transaction'.format(node)
                    try:
                        response = requests.post(
                            url, json={'sender': sender, 'recipient': recipient,
                                       'amount': amount, 'signature': signature}
                        )
                        if response.status_code == 400 or response.status_code == 500:
                            print('Transaction declined, needs to be resolved')
                            return False
                    except requests.exceptions.ConnectionError:
                        continue
            return True
        return False

    def mine_block(self):
        if self.public_key == None:
            return None

        last_block = self.__chain[-1]
        hashed_block = hash_block(last_block)
        proof = self.proof_of_work()
        reward_transaction = Transaction(
            sender='MINING', recipient=self.public_key, signature='', amount=MINING_REWARD)
        copied_transactions = self.__open_transactions[:]
        for tx in copied_transactions:
            if not Wallet.verify_transaction(tx):
                return None

        copied_transactions.append(reward_transaction)
        block = Block(index=len(self.__chain), previous_hash=hashed_block,
                      transactions=copied_transactions, proof=proof)
        self.__chain.append(block)
        self.__open_transactions = []
        self.save_data()

        for node in self.__peer_nodes:
            url = 'http://{}/broadcast_block'.format(node)
            converted_block = block.__dict__.copy()
            converted_block['transactions'] = [
                tx.__dict__ for tx in converted_block['transactions']
            ]
            try:
                response = requests.post(url, json={'block': converted_block})
                if response.status_code == 400 or response.status_code == 500:
                    print('Block declined, needs to be resolved')
                elif response.status_code == 409:
                    self.resolve_conflicts = True
            except requests.exceptions.ConnectionError:
                continue

        return block

    def add_block(self, block):
        transactions = [
            Transaction(
                sender=tx['sender'],
                recipient=tx['recipient'],
                signature=tx['signature'],
                amount=tx['amount']
            )
            for tx in block['transactions']
        ]
        proof_is_valid = Verification.valid_proof(
            transactions=transactions[:-1],
            last_hash=block['previous_hash'],
            proof=block['proof']
        )
        hashes_match = hash_block(self.chain[-1]) == block['previous_hash']
        if not proof_is_valid or not hashes_match:
            return False

        converted_block = Block(
            index=block['index'],
            previous_hash=block['previous_hash'],
            proof=block['proof'],
            timestamp=block['timestamp'],
            transactions=transactions
        )
        self.__chain.append(converted_block)

        stored_transactions = self.__open_transactions[:]
        for itx in transactions:
            for opentx in stored_transactions:
                if itx.sender == opentx.sender and itx.recipient == opentx.recipient and itx.signature == opentx.signature and itx.amount == opentx.amount:
                    try:
                        self.__open_transactions.remove(opentx)
                    except ValueError:
                        print('Item was already removed')

        self.save_data()
        return True

    def resolve_chain_conflicts(self):
        winner_chain = self.__chain
        replace = False
        for node in self.__peer_nodes:
            url = 'http://{}/chain'.format(node)
            try:
                response = requests.get(url)
                node_chain = response.json()
                node_chain = [
                    Block(
                        index=block['index'],
                        previous_hash=block['previous_hash'],
                        proof=block['proof'],
                        timestamp=block['timestamp'],
                        transactions=[
                            Transaction(
                                amount=tx['amount'],
                                recipient=tx['recipient'],
                                sender=tx['sender'],
                                signature=tx['signature']
                            )
                            for tx in block['transactions']
                        ]
                    )
                    for block in node_chain
                ]
                node_chain_len = len(node_chain)
                local_chain_len = len(self.__chain)
                if node_chain_len > local_chain_len and Verification.verify_chain(node_chain):
                    winner_chain = node_chain
                    replace = True
            except requests.exceptions.ConnectionError:
                continue

        self.__chain = winner_chain
        self.resolve_conflicts = False
        if replace:
            self.__open_transactions = []
        self.save_data()
        return replace

    def add_peer_node(self, node):
        self.__peer_nodes.add(node)
        self.save_data()

    def remove_peer_node(self, node):
        self.__peer_nodes.discard(node)
        self.save_data()

    def get_pear_nodes(self):
        return list(self.__peer_nodes)
