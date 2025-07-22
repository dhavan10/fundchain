import unittest
import time
from blockchain import Block, Blockchain

class TestBlockchain(unittest.TestCase):

    def setUp(self):
        self.blockchain = Blockchain()

    def test_genesis_block(self):
        genesis = self.blockchain.chain[0]
        self.assertEqual(genesis.index, 0)
        self.assertEqual(genesis.previous_hash, "0")
        self.assertEqual(genesis.data, {"message": "Genesis Block"})

    def test_add_block(self):
        self.blockchain.add_block({"from": "Gov", "to": "School", "amount": 1000})
        latest = self.blockchain.get_latest_block()
        self.assertEqual(latest.index, 1)
        self.assertEqual(latest.data["from"], "Gov")
        self.assertEqual(latest.data["to"], "School")
        self.assertEqual(latest.data["amount"], 1000)

    def test_hash_calculation(self):
        block = self.blockchain.chain[0]
        expected_hash = block.calculate_hash()
        self.assertEqual(block.hash, expected_hash)

    def test_chain_validation(self):
        self.blockchain.add_block({"from": "Gov", "to": "School", "amount": 1000})
        self.blockchain.add_block({"from": "Gov", "to": "Hospital", "amount": 500})
        self.assertTrue(self.blockchain.is_chain_valid())

        # Tamper with a block data
        self.blockchain.chain[1].data = {"from": "Gov", "to": "Fake", "amount": 9999}
        self.blockchain.chain[1].hash = self.blockchain.chain[1].calculate_hash()
        self.assertFalse(self.blockchain.is_chain_valid())

if __name__ == "__main__":
    unittest.main()
