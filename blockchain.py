import hashlib
import json
from datetime import datetime

class Block:
    def __init__(self, data, previous_hash):
        self.data = data
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        return hashlib.sha256((str(self.data) + self.timestamp + self.previous_hash).encode()).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = [Block({"genesis": "start"}, "0")]

    def add_block(self, data):
        new_block = Block(data, self.chain[-1].hash)
        self.chain.append(new_block)
        return new_block.hash

    def save_chain(self, filename="traffic_chain.json"):
        with open(filename, "w") as f:
            json.dump([{"data": b.data, "timestamp": b.timestamp, "hash": b.hash, "previous_hash": b.previous_hash} 
                       for b in self.chain], f, indent=4)

blockchain = Blockchain()