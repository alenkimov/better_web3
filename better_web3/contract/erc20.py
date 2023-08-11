from functools import cached_property
from typing import TYPE_CHECKING, Iterable

from eth_typing import ChecksumAddress, BlockIdentifier
from web3.types import Wei

from ._abi import ERC20_ABI
from .contract import Contract

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

    @cached_property
    async def name(self) -> str:
        return await self.functions.name().call()

    @cached_property
    async def symbol(self) -> str:
        return await self.functions.symbol().call()

    @cached_property
    async def decimals(self) -> int:
        return await self.functions.decimals().call()

    async def get_balance(
            self,
            address: ChecksumAddress,
            block_identifier: BlockIdentifier = "latest",
    ) -> Wei:
        balance = await self.functions.balanceOf(address).call(block_identifier=block_identifier)
        return balance

    async def get_balances(
            self,
            addresses: Iterable[ChecksumAddress],
            block_identifier: BlockIdentifier = "latest",
            **kwargs,
    ) -> Iterable[dict[str: ChecksumAddress | str, str: Wei]]:
        if not addresses:
            return

        balances = await self.chain.batch_request.contract_request(
            [self.functions.balanceOf(address) for address in addresses],
            block_identifier,
            **kwargs,
        )
        for address, balance_data in zip(addresses, balances):
            yield {"address": address, "balance":  balance_data["result"]}
