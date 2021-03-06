# This is a demo file to simulate the work flow of blockchain.
# Ref: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa.html

# __init__ imports
from datetime import datetime

# get_hash imports
from cryptography.hazmat.primitives import hashes

# save imports
import pickle
from pathlib import Path
import os
import time

# get_path_from_hash imports
import binascii

# have_valid_proof_of_work imports
from config import LEADING_ZEROS_REQUIRED

# generate_proof_of_work imports
import random

class Block:
    '''
    Class for representing blocks.
    previous_hash: hash of previous block class
    data: Data for current block
    '''

    def __init__(self, previous_block):

        # Generate pevious blocks hash
        previous_hash = previous_block.get_hash() if previous_block else None
        # Initialize class object
        self.previous_hash = previous_hash
        self.data = []
        self.creation_time = datetime.now()
        self.nonce = None

    def __repr__(self):
        return (
            f'\nprevious_hash: {self.previous_hash}' +
            f'\ndata: {self.data}'
            f'\nCreated_at: {self.creation_time}\n'
        )

    def get_hash(self):
        '''
        Method to compute hash for self.
        '''
        # Calculate hash
        digest = hashes.Hash(hashes.SHA256())
        digest.update(bytes(str(self.previous_hash), encoding='utf-8'))
        digest.update(bytes(str(self.data), encoding='utf-8'))
        digest.update(bytes(int(time.mktime(self.creation_time.timetuple()))))
        digest.update(bytes(str(self.nonce), encoding='utf-8'))
        return digest.finalize()

    def add_transaction(self, trasnaction):
        '''
        Method to add transaction in this block ledger
        transaction: object of Transaction class
        returns: None
        '''
        self.data.append(trasnaction)

    def have_valid_proof_of_work(self):
        '''
        Method to validate the proof of work by checking number of leading zeros in block's hash.
        returns: True if proof of work is valid else False
        '''
        # Check if hash is matching with required leading zeros
        hash = self.get_hash()
        print(hash)
        if hash.startswith(
            bytes(str('\x00' * LEADING_ZEROS_REQUIRED), encoding='utf-8')
        ):
            return True
        return False

    def generate_proof_of_work(self):
        '''
        Method to do all the computatation to fulfil proof_of_work requirement.
        Tries random nonce until proof of work is validated.
        returns: None
        '''

        while not self.have_valid_proof_of_work():
            self.nonce = ''.join(
                [
                    chr(
                        random.randint(0, 255)
                    ) for _ in range(10 * LEADING_ZEROS_REQUIRED)
                ]
            )
            print(self.nonce)

    def is_valid(self):
        '''
        Method to validate all the transactions added in it 
        returns: True is valid else False
        '''
        for transaction in self.data:
            if not transaction.is_valid:
                return False
        if not self.have_valid_proof_of_work():
            return False
        return True

    def save(self):
        '''
        Method to save current block in blockchain
        returns: None
        '''
        # Write object to file.
        with open(get_path_from_hash(self.get_hash()), 'wb') as block_pickle:
            pickle.dump(self, block_pickle)

        with open('last_block_hash.txt', 'wb') as last_block_hash_file:
            last_block_hash_file.write(self.get_hash())


def get_path_from_hash(hash):
    '''
    Method to generate file path to block_storage from block's hash.
    hash: Hash of the block.
    returns: file path for storing the block in block_storage
    '''
    # Return file path for given hash
    return os.path.join(
        os.path.join(
            os.path.dirname(
                os.path.abspath(__file__)
            ),
            'block_storage'
        ),
        binascii.b2a_hex(hash).decode()
    )


def get_block_from_hash(hash):
    '''
    Method to get block from given hash
    hash: Hash of the block
    returns: Block object for given hash or None
    '''
    # Generate path for given hash
    block_path = get_path_from_hash(hash)

    # If block doesn't exists return None
    if not Path(block_path).exists():
        return None

    block = None

    # Load block from block_storage
    with open(block_path, 'rb') as block_pickle:
        block = pickle.load(block_pickle)

    return block


def get_last_block():
    '''
    Method to get lask block of blockchain
    returns: last block of blockchain or None
    '''

    # Check if last_block_hash exists.
    if Path(__file__).parent.joinpath('last_block_hash.txt').exists():

        # read last block's hash from file
        with open('last_block_hash.txt', 'rb') as last_block_hash_file:
            last_block_hash = last_block_hash_file.read()

            # load block from last block's hash
            return get_block_from_hash(last_block_hash)
