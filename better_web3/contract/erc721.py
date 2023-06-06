from typing import TYPE_CHECKING, cast, Iterable

from eth_abi.exceptions import DecodingError
from eth_typing import ChecksumAddress, BlockIdentifier
from eth_utils import to_checksum_address

from .abi import ERC721_ABI
from .contract import Contract
from .exceptions import InvalidERC721Info
from .model import Erc721Info

if TYPE_CHECKING:
    from ..chain import Chain


class ERC721(Contract):
    """
    Реализация ERC721 контракта
    """

    def __init__(
            self,
            chain: "Chain",
            address: ChecksumAddress | str,
            abi=None,
    ):
        abi = abi or ERC721_ABI
        super().__init__(chain, address, abi)

    def get_balance(
            self,
            address: ChecksumAddress,
            block_identifier: BlockIdentifier | None = "latest",
    ) -> int:
        balance = self.functions.balanceOf(address).call(block_identifier=block_identifier)
        return balance

    def get_balances(
            self,
            addresses: Iterable[ChecksumAddress],
            block_identifier: BlockIdentifier | None = "latest",
    ) -> dict[ChecksumAddress: int]:
        """
        If there's a problem with a token_address `0` will be returned for balance
        """
        if not addresses:
            return []
        addresses = list(addresses)
        balances = self.chain.batch_call(
            [self.functions.balanceOf(address) for address in addresses],
            block_identifier=block_identifier,
            raise_exception=False,
        )
        return {address: balance if isinstance(balance, int) else 0
                for address, balance in zip(addresses, balances)}

    def get_owners(
            self,
            token_ids: Iterable[int],
            block_identifier: BlockIdentifier | None = "latest",
    ) -> dict[int: ChecksumAddress]:
        if not token_ids:
            return []
        token_ids = list(token_ids)
        owners = self.chain.batch_call(
            [self.functions.ownerOf(token_id) for token_id in token_ids],
            block_identifier=block_identifier,
            raise_exception=False,
        )
        return {token_id: to_checksum_address(owner) if isinstance(owner, str) else None
                for token_id, owner in zip(token_ids, owners)}

    def get_token_uris(
            self,
            token_ids: Iterable[int],
            block_identifier: BlockIdentifier | None = "latest",
    ) -> dict[int: str]:
        if not token_ids:
            return []
        token_ids = list(token_ids)
        token_uris = self.chain.batch_call(
            [self.functions.tokenURI(token_id) for token_id in token_ids],
            block_identifier=block_identifier,
            raise_exception=False,
        )
        return {token_id: token_uri if isinstance(token_uri, str) else None
                for token_id, token_uri in zip(token_ids, token_uris)}

    def get_info(self) -> Erc721Info:
        """
        Get erc721 information (`name`, `symbol`)
        Use batching to get all info in the same request
        """
        try:
            name, symbol = cast(
                list[str],
                self.chain.batch_call(
                    [
                        self.functions.name(),
                        self.functions.symbol(),
                    ]
                ),
            )
            return Erc721Info(name, symbol)
        except (DecodingError, ValueError):  # Not all the ERC721 have metadata
            raise InvalidERC721Info
