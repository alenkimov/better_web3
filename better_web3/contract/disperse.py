from eth_typing import ChecksumAddress
from web3.contract.async_contract import AsyncContractFunction
from web3.types import Wei

from ._abi import DISPERSE_ABI
from .contract import Contract

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..chain import Chain


DISPERSE_CONTRACT_ADDRESS = "0xD152f549545093347A162Dce210e7293f1452150"


class Disperse(Contract):
    def __init__(
        self,
        chain: "Chain",
        address: ChecksumAddress | str = None,
        abi=None,
    ):
        address = address or DISPERSE_CONTRACT_ADDRESS
        abi = abi or DISPERSE_ABI
        super().__init__(chain, address, abi)

    def disperse_ether(
            self,
            recipients: list[ChecksumAddress | str],
            values: list[Wei | int],
    ) -> AsyncContractFunction:
        """
        disperseEther(address[] recipients, uint256[] values)
        """
        return self.functions.disperseEther(recipients, values)
