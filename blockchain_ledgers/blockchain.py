# THis file demonstrates how blockchain works and 

# Signature imports
from signatures import *

# Block imports
from block import *

# Transaction imports
from transactions import Transaction

from datetime import datetime

# Create multiple pair of keys for testing
pu1, pr1 = generate_keys(return_bytes=True)
pu2, pr2 = generate_keys(return_bytes=True)

# Deserialize the private key
pr1 = load_private_key_from_pem(pr1)
pr2 = load_private_key_from_pem(pr1)

# Get last block
last_block = get_last_block()
print('Adding new block to blockchain')

# Create new block
block = Block(last_block)

# Normal transaction
transaction = Transaction()
transaction.add_input(pu1, 1)
transaction.add_output(pu1, 1)
transaction.sign(pr1)

# Normal transaction
transaction1 = Transaction()
transaction1.add_input(pu2, 1)
transaction1.add_output(pu2, 1)
transaction1.sign(pr2)

# Add transactions to block
block.add_transaction(transaction)
block.add_transaction(transaction1)
start = datetime.now()
block.generate_proof_of_work()
print(f'Time taken to calculate proof_of_work is {datetime.now() - start}')

# Save block to blockchain
block.save()


