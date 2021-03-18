# Dome file to understnd and buid transaction and transation validations.
# Ref: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa.html

# Signatures immports
from signatures import (generate_keys,
                        verify,
                        sign_message,
                        load_private_key_from_pem,
                        load_public_key_from_pem
                        )

# configuration imports
from config import MINING_REWARD_AMOUNT_LIMIT


def transaction_sum(transactions):
    '''
    Method to calculate sum of amounts in transaction
    transactions: list of inputs/outputs
    returns: sum of amounts in inputs/outputs.
    '''
    sum_ = 0
    for transaction in transactions:
        sum_ = sum_ + transaction[1]
    return sum_


class Transaction:
    '''
    Clas for representing Transactions.
    '''

    def __init__(self):
        self.inputs = []
        self.outputs = []
        self.signatures = []
        self.required_list = []

    def __repr__(self):
        '''
        Method to return all the data in string format when called by str merhod.
        returns: returns all the data in string format.
        '''
        # Add inputs to representation
        transaction_string = 'Inputs:\n'
        for sender, amount in self.inputs:
            transaction_string += f'rececived {amount} from {sender} \n\n'

        # Add outputs to representation
        transaction_string += 'Outputs:\n'
        for receiver, amount in self.outputs:
            transaction_string += f'sent {amount} to {receiver} \n\n'

        # Add signatures to representation
        transaction_string += 'Signatures:\n'
        for signature in self.signatures:
            transaction_string += f'{signature}\n'

        # Add required signs to representation
        transaction_string += 'Required Signs:\n'
        for required in self.required_list:
            transaction_string += f'{required}\n'

        # return all the representation
        return transaction_string

    def add_input(self, from_address, amount):
        '''
        A method to record receiving transaction in ledger.
        from_address: Sender who had sent the amount
        amount: Amount received.
        returns: None
        '''
        self.inputs.append((from_address, amount))

    def add_output(self, to_address, amount):
        '''
        A method to record spending transaction from user.
        to_address: Public address(Public key) of receiver
        amount: amount to be sent
        returns: None
        '''
        self.outputs.append((to_address, amount))

    def __gather(self):
        '''
        Private method to combine all inputs and outputs. 
        Not required to be exact format.
        returns: None
        '''
        return bytes(str([self.inputs, self.outputs]), 'utf-8')

    def sign(self, private_key):
        '''
        A method to sign all the transactions in this ledger
        private: private key to sign the doc
        returns: None
        '''
        message = self.__gather()
        signature = sign_message(private_key, message)
        self.signatures.append(signature)

    def add_required(self, address):
        '''
        A method to add additonal user's verification to the ledger.(Escrow transactions)
        address: Public address of escrow user.
        returns: None
        '''
        self.required_list.append(address)

    def is_valid(self):
        '''
        A method to validate all the trasaction in the ledger. \
            Uses all the input & required public key to vetify the trasaction.
        returns: True if trasaction is valid else false.
        '''

        # validate any negative tranaction
        if sum(1 for amount in self.inputs+self.outputs if amount[1] < 0) > 0:
            print('Negative value found')
            return False

        # Validate the input must be equal or grater than outputs
        if transaction_sum(self.inputs) - transaction_sum(self.outputs) - \
                MINING_REWARD_AMOUNT_LIMIT > 0.00000001:
            print('Outputs are greater than input.')
            return False

        # validate the signatures.
        signatures_validated = 0
        message = self.__gather()

        # Validate signature on the basis of inputs.
        for public_key, _ in self.inputs:
            for signature in self.signatures:
                if verify(signature, message, public_key):
                    signatures_validated = signatures_validated + 1

        # Validate signature on the basis of escrew signatures.
        for public_key in self.required_list:
            for signature in self.signatures:
                if verify(signature, message, public_key):
                    signatures_validated = signatures_validated + 1

        # return the signature validation count.
        return signatures_validated == len(self.signatures)


def print_result(description, expected, actual, reason=None):
    '''
    Method to print results in format.
    description: Description for the test.
    expected: Expected result of the test.
    actual: Actual result of the test.
    reason: Failure reason of test.
    '''
    print(
        f'Description: {description} \n' +
        f'Expected result: {"Verified" if expected else "Rejected"} \n' +
        f'Actual result: {"Verified" if actual else "Rejected"} \n' +
        f'Reason: {reason}\n\n'
    )


if __name__ == "__main__":

    print('Executing tests for Blockchain transactions.\n\n')

    # Create multiple pair of keys for testing
    pu1, pr1 = generate_keys()
    pu2, pr2 = generate_keys()
    pu3, pr3 = generate_keys()
    pu4, pr4 = generate_keys()
    pu5, pr5 = generate_keys()

    # Normal transaction
    transaction = Transaction()
    transaction.add_input(pu1, 1)
    transaction.add_output(pu1, 1)
    transaction.sign(pr1)

    print_result(
        description='Normal transation with one input,' +
        ' one output and one signature',
        expected=True,
        actual=transaction.is_valid(),
        reason=None
    )

    # Two output single signture
    transaction = Transaction()
    transaction.add_input(pu1, 3)
    transaction.add_output(pu2, 1)
    transaction.add_output(pu3, 1)
    transaction.sign(pr1)

    print_result(
        description='Normal transation with one input,' +
        ' two output and one signature',
        expected=True,
        actual=transaction.is_valid(),
        reason=None
    )

    # normal signature with one escrow
    transaction = Transaction()
    transaction.add_input(pu1, 1)
    transaction.add_output(pu2, 1)
    transaction.sign(pr1)
    transaction.add_required(pu4)
    transaction.sign(pr4)

    print_result(
        description='Normal transation with one input,' +
        ' two output, one signature and additional escrow',
        expected=True,
        actual=transaction.is_valid(),
        reason=None
    )

    # Wrong signature
    transaction = Transaction()
    transaction.add_input(pu1, 1)
    transaction.add_output(pu2, 1)
    transaction.sign(pr3)

    print_result(
        description='Transaction with wrong signature,' +
        ' one input, one output',
        expected=False,
        actual=transaction.is_valid(),
        reason='Signed by wrong signature'
    )

    # Wrong signature, right escrow
    transaction = Transaction()
    transaction.add_input(pu1, 1)
    transaction.add_output(pu2, 1)
    transaction.sign(pr3)
    transaction.add_required(pu4)
    transaction.sign(pr4)

    print_result(
        description='Normal transation with one input,' +
        ' one input, one output and additional escrow',
        expected=False,
        actual=transaction.is_valid(),
        reason='Signed by wrong signature'
    )

    # output more than input
    transaction = Transaction()
    transaction.add_input(pu1, 1)
    transaction.add_output(pu2, 2)
    transaction.sign(pr3)
    transaction.add_required(pu4)
    transaction.sign(pr4)

    print_result(
        description='Tranction with greater output than input',
        expected=False,
        actual=transaction.is_valid(),
        reason='Output is 2 while input is 1'
    )

    # negative input
    transaction = Transaction()
    transaction.add_input(pu1, -1)
    transaction.add_output(pu2, -1)
    transaction.sign(pr3)
    transaction.add_required(pu4)
    transaction.sign(pr4)

    print_result(
        description='Tranction with negative output and input',
        expected=False,
        actual=transaction.is_valid(),
        reason='Negative input and output'
    )

    # Temparing the transaction
    transaction = Transaction()
    transaction.add_input(pu1, 1)
    transaction.add_output(pu2, 1)
    transaction.add_output(pu3, 1)
    transaction.sign(pr1)
    transaction.outputs[0] = (pu5, 2)

    print_result(
        description='Normal transation with one input,' +
        ' two output and one signature but tempred',
        expected=False,
        actual=transaction.is_valid(),
        reason='Trasnaction tempered after signing'
    )
