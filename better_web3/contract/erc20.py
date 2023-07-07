from typing import TYPE_CHECKING, Iterable

from eth_typing import ChecksumAddress, BlockIdentifier
from web3.types import Wei

from ._abi import ERC20_ABI
from .contract import Contract
from ..utils import cache

if TYPE_CHECKING:
    from ..chain import Chain


class ERC20(Contract):
    def __init__(
            self,
            chain: "Chain",
            address: ChecksumAddress | str,
            abi=None,
    ):
        abi = abi or ERC20_ABI
        super().__init__(chain, address, abi)

    @property
    @cache
    def name(self) -> str:
        return self.functions.name().call()

    @property
    @cache
    def symbol(self) -> str:
        return self.functions.symbol().call()

    @property
    @cache
    def decimals(self) -> int:
        return self.functions.decimals().call()

    def get_balance(
            self,
            address: ChecksumAddress,
            block_identifier: BlockIdentifier = "latest",
    ) -> Wei:
        balance = self.functions.balanceOf(address).call(block_identifier=block_identifier)
        return balance

    def get_balances(
            self,
            addresses: Iterable[ChecksumAddress],
            block_identifier: BlockIdentifier = "latest",
            **kwargs,
    ) -> Iterable[dict[str: ChecksumAddress | str, str: Wei]]:
        if not addresses:
            return []

        balances = self.chain.batch_request.contract_request(
            [self.functions.balanceOf(address) for address in addresses],
            block_identifier,
            **kwargs,
        )
        for address, balance_data in zip(addresses, balances):
            yield {"address": address, "balance":  balance_data["result"]}
