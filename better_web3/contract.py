from typing import TYPE_CHECKING

from eth_typing import Address, ChecksumAddress
from web3.types import ENS, ABI
from web3 import Web3
from web3.contract.async_contract import (
    AsyncContract,
    AsyncContractFunctions,
    AsyncContractEvents,
)

if TYPE_CHECKING:
    from .chain import Chain


class Contract:
    DEFAULT_ABI = None
    DEFAULT_ADDRESS = None

    def __init__(
            self,
            chain: "Chain",
            address: Address | ChecksumAddress | ENS = None,
            abi: ABI | str = None,
    ):
        self._chain = chain
        abi = abi or self.DEFAULT_ABI
        address = address or self.DEFAULT_ADDRESS
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
