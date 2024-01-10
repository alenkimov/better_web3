from typing import TYPE_CHECKING

from eth_typing import ChecksumAddress
from eth_utils import to_checksum_address
from web3 import Web3
from web3.contract.async_contract import (
    AsyncContract,
    AsyncContractFunctions,
    AsyncContractEvents,
)
from web3.types import ABI

if TYPE_CHECKING:
    from ..chain import Chain


class Contract:
    def __init__(self, chain: "Chain", address: ChecksumAddress | str, abi):
        if isinstance(address, str):
            address = to_checksum_address(address)
        self._chain = chain
        self._contract: AsyncContract = self._chain.w3.eth.contract(address, abi=abi)

    def __str__(self):
        return self.address

    def __repr__(self):
        return f"{self.__class__.__name__}(address={self.address}, chain.name={self.chain.name})"

    @property
    def w3(self) -> Web3:
        return self._chain.w3

    @property
    def chain(self) -> "Chain":
        return self._chain

    @property
    def contract(self) -> AsyncContract:
        return self._contract

    @property
    def address(self) -> ChecksumAddress:
        return self._contract.address

    @property
    def abi(self) -> ABI:
        return self._contract.abi

    @property
    def functions(self) -> AsyncContractFunctions:
        return self._contract.functions

    @property
    def events(self) -> AsyncContractEvents:
        return self._contract.events
