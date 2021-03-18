# This is a demo file to simulate the work flow of blockchain.
# Ref: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa.html

# get_hash imports
from cryptography.hazmat.primitives import hashes

# Main imports
import os
import pickle
import random
from collections import OrderedDict

class Block:
    '''
    Class for representing blocks.
    previous_hash: hash of previous block class
    data: Data for current block
    '''

    def __init__(self, previous_block, data):
        
        # Generate pevious blocks hash
        previous_hash = previous_block.get_hash() if previous_block else None
        
        # Initialize class object
        self.previous_hash = previous_hash
        self.data = data

    def __repr__(self):
        return (
            f'\nprevious_hash: {self.previous_hash}'+
            f'\ndata: {self.data}\n'
        )

    def get_hash(self):
        '''
        Method to compute hash for self.
        '''
        # Calculate hash
        digest = hashes.Hash(hashes.SHA256())
        if self.previous_hash:
            digest.update(bytes(self.previous_hash))
        digest.update(bytes(self.data))
        return digest.finalize()

def get_user_response():
    '''
    Mehtod to get input
    '''
    print(
        (
            "Press 1 to add new block\n"+
            "Press 2 for searching ledger in blockchain\n"+
            "Press 3 to temper any block\n"+
            "Press 4 to detect temperation in blockchain\n"+
            "Press 5 to terminate the programm"
        )
    )
    return input()

def get_data():
    '''
    Method to get input of file name and read the data
    '''
    # Get valid file name
    data_file = input('Please input ledger file name\n')
    while not os.path.exists('ledgers/'+data_file):
        data_file = input(
            'File not found,Please input ledger file name\n'
        )

    # read data and return
    with open('ledgers/'+data_file, 'rb') as data_read:
        data = data_read.read()
    return data

if __name__ == '__main__':
    # Get blockchain or create new
    try:
        with open('blockchain/blockchain.pickle', 'rb') as block_file:
            blockchain = pickle.load(block_file)
    except:
        blockchain = OrderedDict()

    print('Welcome to blockchain simulation\n')
    
    # Infinite loop
    while True:
        # Get user input
        response = get_user_response()

        # Validate user response
        if response not in ['1','2','3','4','5']:
            print('Wrong input, Please follow the below instructions')
            continue
 
        else:

            # Add ledger to blockchain
            if response == '1':
                # get ledger
                data = get_data()
                # get last block of blockchain
                last_block = list(blockchain.values())[-1] if \
                    len(list(blockchain.values())) > 0 else None

                # Create new block
                block = Block(last_block, data)

                # Add block to blockchain
                blockchain.update(
                    {
                        block.get_hash(): block
                    }
                )

                print('New block added successfully')

            # Search ledger in blockchain
            elif response == '2':

                # get last block
                last_block = list(blockchain.values())[-1] if \
                    len(list(blockchain.values())) > 0 else None

                if last_block is None:
                    print('Blockchain is empty\n')
                    continue
            
                # get ledger
                data = get_data()

                # Search block in blockchain
                while data != last_block.data:
                    # If reached to first block
                    if last_block.previous_hash is None:
                        print('Ledger not found in blockchain\n')
                        break
                    
                    # Get previous block
                    last_block = blockchain.get(last_block.previous_hash, None)
                    
                    # If last block is tempered the it won't be found
                    if last_block is None:
                        print('Blockchain tempered\n')
                        break 

                # If we found matching block
                if data == last_block.data:
                    print('Block found in Blockchain\n')

            # Temparing blockchain
            elif response == '3': 
                # Check if blank blockchain
                if len(blockchain.values()) < 1:
                    print(
                        "Can't temper single block or empty blockchain,"+
                        " Please add blocks first\n"
                        )
                    continue
                else:
                    # Update any random block in blockchain
                    random_index = random.randint(
                        1, 
                        len(blockchain.values())-1
                    )
                    key, block = list(blockchain.items())[random_index]
                    
                    blockchain.pop(key)

                    # temper the block
                    block.data = block.data + b'  dfgsdfgkjsembm hdfghg'

                    # Update to blockchain
                    blockchain.update(
                        {
                            block.get_hash(): block
                        }
                    )
                    # blockchain = temp_dict
                    print(f'Block at number {random_index} tempered.')
                    print('Try searching index now to validate.\n')


            elif response == '4':

                # get last block
                last_block = list(blockchain.values())[-1] if \
                    len(list(blockchain.values())) > 0 else None
                
                while last_block.previous_hash:

                    # Get previous block
                    last_block = blockchain.get(last_block.previous_hash, None)

                    # If last block is tempered the it won't be found
                    if last_block is None:
                        print('Blockchain tempered\n')
                        break 

                # If we found matching block
                if last_block is not None:
                    if last_block.previous_hash is None:
                        print('Tempering Not detected.\n')

            # Save blockchain and terminate
            else:
                with open('blockchain/blockchain.pickle', 'wb') as block_file:
                    pickle.dump(blockchain,block_file)
                    print('Blockchain saved...')
                exit()