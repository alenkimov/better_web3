from functools import cached_property
from typing import TYPE_CHECKING, Iterable

from eth_typing import ChecksumAddress, BlockIdentifier
from eth_utils import to_checksum_address

from ._abi import ERC721_ABI
from .contract import Contract

if TYPE_CHECKING:
    from ..chain import Chain


class ERC721(Contract):
    def __init__(
            self,
            chain: "Chain",
            address: ChecksumAddress | str,
            abi=None,
    ):
        abi = abi or ERC721_ABI
        super().__init__(chain, address, abi)

    @cached_property
    def name(self) -> str:
        return self.functions.name().call()

    @cached_property
    def symbol(self) -> str:
        return self.functions.symbol().call()

    def get_balance(
            self,
            address: ChecksumAddress,
            block_identifier: BlockIdentifier = "latest",
    ) -> int:
        return self.functions.balanceOf(address).call(block_identifier=block_identifier)

    async def get_balances(
            self,
            addresses: Iterable[ChecksumAddress],
            block_identifier: BlockIdentifier = "latest",
            **kwargs,
    ) -> Iterable[dict[str: ChecksumAddress, str: int]]:
        if not addresses:
            return

        balances = await self.chain.batch_request.contract_request(
            [self.functions.balanceOf(address) for address in addresses],
            block_identifier,
            **kwargs,
        )
        for address, balance_data in zip(addresses, balances):
            yield {"address": address, "balance":  balance_data["result"]}

    async def get_owners(
            self,
            token_ids: Iterable[int],
            block_identifier: BlockIdentifier = "latest",
            **kwargs,
    ) -> Iterable[dict[str: int, str: ChecksumAddress]]:
        if not token_ids:
            return

        owners = await self.chain.batch_request.contract_request(
            [self.functions.ownerOf(token_id) for token_id in token_ids],
            block_identifier,
            **kwargs,
        )
        for token_id, owner_data in zip(token_ids, owners):
            yield {"token_id": token_id, "owner": to_checksum_address(owner_data["result"])}

    async def get_token_uris(
            self,
            token_ids: Iterable[int],
            block_identifier: BlockIdentifier = "latest",
            **kwargs,
    ) -> Iterable[dict[str: int, str: str]]:
        if not token_ids:
            return

        token_uris = await self.chain.batch_request.contract_request(
            [self.functions.tokenURI(token_id) for token_id in token_ids],
            block_identifier=block_identifier,
            **kwargs,
        )
        for token_id, uri_data in zip(token_ids, token_uris):
            yield {"token_id": token_id, "uri": uri_data["result"]}
