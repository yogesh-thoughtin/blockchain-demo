# Demo file to understand and build digital signature demo

# Generete key imports
from cryptography.hazmat.primitives.asymmetric import rsa

# Writing files imports
import os
from cryptography.hazmat.primitives import serialization

# Signature imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Verify imports
from cryptography.exceptions import InvalidSignature

# Main function imports
import sys


def write_keys_to_files(private_key):
    '''
    A funtion to write keys in the files:
        private_key: RSAPrivateKey object
        returns: None
    '''

    # Create dir if doesn't exists
    if not os.path.exists('keys'):
        os.makedirs('keys')

    # Genterate private key bytes
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption() # for no encryption
        # encryption_algorithm=serialization.BestAvailableEncryption( # for password encryption
        #     b'password_for_encryption'
        # )
    )
    # Write bytes to file
    with open('keys/private.pem','wb') as key:
        key.write(private_key_bytes)

    # Generate public key bytes
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1
    )
    # Write bytes to file
    with open('keys/public.pem','wb') as key:
        key.write(public_key_bytes)


def generate_keys(write_to_file=False):
    '''
    A method to generate public and private keys using RSA algorithm
        write_to_file: Boolean to write keys on file or not.
        returns: returns public_key and private_key
    '''
    # generate  RSAPrivateKey object
    private_key = rsa.generate_private_key(
        public_exponent=65537, # public exponent must be 65537 as per doc, except for custom backends
        key_size=4096, # key can between 512 to 4096, Bigger the size, more hard to crack
    )
    
    # Write key to files
    if write_to_file:
        write_keys_to_files(private_key)
    
    # get public_key for private key
    public_key = private_key.public_key()
    
    return public_key, private_key


def sign_message(private_key, message):
    '''
    A method to sign the message using private key.
        private_key: 
    '''
    # Create signed message
    signed_message = private_key.sign(
        data=message,
        padding=padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        algorithm=hashes.SHA256()
    )
    return signed_message

def verify(signed_message, message, public_key):
    '''
    A method to verify the signature of message.
        signed_message: Signed hash for original message
        message: Plaintext message
        public_key: Public key of PKI 
        returns: boolean, True if signature is verified else False.
    '''
    try:
        # Verify signrature with actual message and return true
        public_key.verify(
            signature=signed_message,
            data=message,
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            algorithm=hashes.SHA256()
        )
        return True
    # Return false when invalid signature.
    except InvalidSignature:
        return False

if __name__ == '__main__':
    message = b'random_message'

    # Example with writing keys into files
    if len(sys.argv) > 1:
        # Generate keys and write it files
        generate_keys(write_to_file=True)
        # Read private key
        with open('keys/private.pem', 'rb') as key:
            private_key = serialization.load_pem_private_key(
                key.read(),
                password=None
            ) 
        # Read public keys
        with open('keys/public.pem', 'rb') as key:
            public_key = serialization.load_pem_public_key(
                key.read()
            )

    # Example without storin keys to files
    else:
        public_key, private_key = generate_keys()
    
    # Sign message
    signed_message = sign_message(private_key, message)
    
    # Verify message
    if verify(signed_message, message, public_key):
        print(
            f'''
                message        :"{message}",
                veified successfully....
            '''
        )
    else:
        print(
            f'''
                message        : "{message}",
                verification failed....
            ''' 
        )