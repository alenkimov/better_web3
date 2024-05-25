from eth_typing import ChecksumAddress

from .chain import Chain


class Contract:
    ABI = None
    DEFAULT_ADDRESS: ChecksumAddress = None

    def __init__(self, chain: Chain, address: ChecksumAddress = None):
        self.chain = chain
        self.contract = self.chain.eth.contract(
            address or self.DEFAULT_ADDRESS, abi=self.ABI)

    def __repr__(self):
        return f"{self.__class__.__name__}(address={self.contract.address}, chain.name={self.chain.name})"
