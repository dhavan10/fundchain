import hashlib
import json
import time
import os
import csv
import glob
from getpass import getpass
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime

DATA_FILE = "data/blockchain.json"
BACKUP_FILE = "data/blockchain_backup.json"  # auto backup file (latest)
CSV_FILE = "data/blockchain_export.csv"
KEYS_DIR = "keys"

ADMIN_PASSWORD = "admin123"  # Change this before production


class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = f"{self.index}{self.timestamp}{json.dumps(self.data)}{self.previous_hash}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "hash": self.hash
        }

    @staticmethod
    def from_dict(data):
        block = Block(
            index=data["index"],
            timestamp=data["timestamp"],
            data=data["data"],
            previous_hash=data["previous_hash"]
        )
        return block


class Blockchain:
    def __init__(self):
        self.chain = []
        self.load_chain()

    def create_genesis_block(self):
        return Block(0, time.time(), {"message": "Genesis Block"}, "0")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, data):
        last_block = self.get_latest_block()
        new_block = Block(
            index=last_block.index + 1,
            timestamp=time.time(),
            data=data,
            previous_hash=last_block.hash
        )
        self.chain.append(new_block)
        self.save_chain()
        print("✅ Block added successfully!")

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]
            if current.hash != current.calculate_hash() or current.previous_hash != previous.hash:
                return False
        return True

    def save_chain(self):
        if not os.path.exists("data"):
            os.makedirs("data")
        with open(DATA_FILE, "w") as f:
            json.dump([block.to_dict() for block in self.chain], f, indent=4)
        self.backup_chain()  # automatic latest backup

    def load_chain(self):
        if not os.path.exists(DATA_FILE):
            self.chain = [self.create_genesis_block()]
            self.save_chain()
        else:
            with open(DATA_FILE, "r") as f:
                data = json.load(f)
                self.chain = [Block.from_dict(b) for b in data]

    def backup_chain(self):
        with open(BACKUP_FILE, "w") as f:
            json.dump([block.to_dict() for block in self.chain], f, indent=4)

    def versioned_backup(self):
        if not os.path.exists("data"):
            os.makedirs("data")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"data/blockchain_backup_{timestamp}.json"
        with open(filename, "w") as f:
            json.dump([block.to_dict() for block in self.chain], f, indent=4)
        print(f"✅ Versioned backup created: {filename}")

    def list_versioned_backups(self):
        files = glob.glob("data/blockchain_backup_*.json")
        if not files:
            print("❌ No versioned backups found.")
            return []
        print("\nAvailable backups:")
        for i, file in enumerate(files):
            print(f"{i + 1}. {file}")
        return files

    def restore_versioned_backup(self, filename):
        if os.path.exists(filename):
            with open(filename, "r") as f:
                data = json.load(f)
                self.chain = [Block.from_dict(b) for b in data]
            self.save_chain()
            print(f"✅ Restored blockchain from {filename}")
        else:
            print("❌ Backup file not found.")

    def restore_backup(self):
        if os.path.exists(BACKUP_FILE):
            with open(BACKUP_FILE, "r") as f:
                data = json.load(f)
                self.chain = [Block.from_dict(b) for b in data]
            self.save_chain()
            print("✅ Blockchain restored from latest backup.")
        else:
            print("❌ Backup file not found.")

    def export_to_csv(self):
        if not os.path.exists("data"):
            os.makedirs("data")
        with open(CSV_FILE, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Index", "Timestamp", "Data", "Prev Hash", "Hash"])
            for block in self.chain:
                writer.writerow([
                    block.index,
                    time.ctime(block.timestamp),
                    json.dumps(block.data),
                    block.previous_hash,
                    block.hash
                ])
        print(f"✅ Blockchain data exported to {CSV_FILE}")

    def reset_chain(self):
        self.chain = [self.create_genesis_block()]
        self.save_chain()
        print("🗑️ Blockchain has been reset!")


class User:
    def __init__(self, name):
        self.name = name
        self.private_key_path = os.path.join(KEYS_DIR, f"{name}_private.pem")
        self.public_key_path = os.path.join(KEYS_DIR, f"{name}_public.pem")
        self.generate_keys()

    def generate_keys(self):
        if not os.path.exists(KEYS_DIR):
            os.makedirs(KEYS_DIR)
        if not os.path.exists(self.private_key_path):
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            with open(self.private_key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            public_key = private_key.public_key()
            with open(self.public_key_path, "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))


def main():
    bc = Blockchain()
    print("\n🔐 Welcome to FundChain — Blockchain-based Fund Tracker")

    while True:
        print("\nMenu:")
        print("1. Add Fund Transfer")
        print("2. Display Blockchain")
        print("3. Validate Blockchain")
        print("4. Export Blockchain to CSV")
        print("5. Restore Blockchain from Latest Backup")
        print("6. Reset Blockchain (Admin Only)")
        print("7. Exit")
        print("8. Manual Versioned Backup")
        print("9. List Versioned Backups")
        print("10. Restore Versioned Backup")

        choice = input("Enter your choice: ")

        if choice == "1":
            sender = input("From: ")
            receiver = input("To: ")
            amount = input("Amount: ")
            user = User(sender)
            bc.add_block({"from": sender, "to": receiver, "amount": amount})

        elif choice == "2":
            for block in bc.chain:
                print("\n-----------------------------")
                print(f"Index: {block.index}")
                print(f"Timestamp: {time.ctime(block.timestamp)}")
                print(f"Data: {block.data}")
                print(f"Hash: {block.hash}")
                print(f"Prev Hash: {block.previous_hash}")

        elif choice == "3":
            print("✅ Chain is valid!" if bc.is_chain_valid() else "❌ Blockchain has been tampered!")

        elif choice == "4":
            bc.export_to_csv()

        elif choice == "5":
            bc.restore_backup()

        elif choice == "6":
            pwd = getpass("Enter Admin Password: ")
            if pwd == ADMIN_PASSWORD:
                confirm = input("Are you sure? This will delete the current chain. (yes/no): ")
                if confirm.lower() == "yes":
                    bc.reset_chain()
            else:
                print("❌ Incorrect password!")

        elif choice == "7":
            print("👋 Exiting FundChain. Goodbye!")
            break

        elif choice == "8":
            bc.versioned_backup()

        elif choice == "9":
            bc.list_versioned_backups()

        elif choice == "10":
            backups = bc.list_versioned_backups()
            if backups:
                selection = input("Enter the number of the backup to restore: ")
                try:
                    index = int(selection) - 1
                    if 0 <= index < len(backups):
                        bc.restore_versioned_backup(backups[index])
                    else:
                        print("❌ Invalid selection.")
                except ValueError:
                    print("❌ Please enter a valid number.")
        else:
            print("❌ Invalid choice. Try again.")


if __name__ == "__main__":
    main()
