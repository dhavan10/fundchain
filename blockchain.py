import hashlib
import json
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        """
        data: {
          "from": str,
          "to": str,
          "amount": float,
          "signature": bytes (base64 string in JSON),
          "public_key": bytes (base64 string in JSON)
        }
        """
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        # Exclude signature and public key to avoid circular dependency in hash
        data_copy = self.data.copy()
        data_copy.pop("signature", None)
        data_copy.pop("public_key", None)
        block_string = f"{self.index}{self.timestamp}{json.dumps(data_copy, sort_keys=True)}{self.previous_hash}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def verify_signature(self):
        if "signature" not in self.data or "public_key" not in self.data:
            return False

        signature = bytes.fromhex(self.data["signature"])
        public_key_bytes = bytes.fromhex(self.data["public_key"])

        public_key = serialization.load_pem_public_key(public_key_bytes)

        # The original message is the transaction data without signature/public_key
        message = json.dumps({
            "from": self.data["from"],
            "to": self.data["to"],
            "amount": self.data["amount"]
        }, sort_keys=True).encode()

        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False


class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        return Block(0, time.time(), {"message": "Genesis Block"}, "0")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, new_data):
        latest_block = self.get_latest_block()
        new_block = Block(
            index=latest_block.index + 1,
            timestamp=time.time(),
            data=new_data,
            previous_hash=latest_block.hash
        )
        self.chain.append(new_block)

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            prev = self.chain[i - 1]
            curr = self.chain[i]

            # Check hash validity
            if curr.hash != curr.calculate_hash():
                return False

            # Check previous hash link
            if curr.previous_hash != prev.hash:
                return False

            # Verify digital signature for each block (skip genesis)
            if not curr.verify_signature():
                return False
        return True


# Helper functions for key generation and signing (can be imported elsewhere)

def generate_keys():
    """
    Generate RSA private and public keys, return them as PEM bytes.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def sign_transaction(private_pem, transaction_data):
    """
    Sign the transaction_data dict (without signature/public_key).
    private_pem: PEM bytes of private key
    transaction_data: dict with keys 'from', 'to', 'amount'
    Returns signature bytes.
    """
    private_key = serialization.load_pem_private_key(private_pem, password=None)

    message = json.dumps(transaction_data, sort_keys=True).encode()

    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature
