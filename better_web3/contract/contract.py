from typing import TYPE_CHECKING

from eth_typing import ChecksumAddress
from eth_utils import to_checksum_address
from web3 import Web3
from web3.contract.contract import Contract as Web3Contract
from web3.contract.contract import ContractEvents, ContractFunctions

if TYPE_CHECKING:
    from ..chain import Chain


class Contract:
    def __init__(self, chain: "Chain", address: ChecksumAddress | str, abi):
        if isinstance(address, str):
            address = to_checksum_address(address)
        self._chain = chain
        self._contract = self._chain.w3.eth.contract(address, abi=abi)

    @property
    def w3(self) -> Web3:
        return self._chain.w3

    @property
    def chain(self) -> "Chain":
        return self._chain

    @property
    def contract(self) -> Web3Contract:
        return self._contract

    @property
    def address(self) -> str:
        return self._contract.address

    @property
    def abi(self):
        return self._contract.abi

    @property
    def functions(self) -> ContractFunctions:
        return self._contract.functions

    @property
    def events(self) -> ContractEvents:
        return self._contract.events
