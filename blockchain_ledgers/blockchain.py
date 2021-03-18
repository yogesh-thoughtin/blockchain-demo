

from signatures import *

from block import *

from transactions import Transaction

# Create multiple pair of keys for testing
pu1, pr1 = generate_keys(return_bytes=True)

pr1 = load_private_key_from_pem(pr1)

last_block = get_last_block()
print('Adding new block to blockchain')
block = Block(last_block)

# Normal transaction
transaction = Transaction()
transaction.add_input(pu1, 1)
transaction.add_output(pu1, 1)
transaction.sign(pr1)

block.add_transaction(transaction)
block.save()

print('New block added to the blockchain')

print('Printing all blocks')

last_block = get_last_block()
while last_block.previous_hash:
    last_block = get_block_from_hash(last_block.previous_hash)