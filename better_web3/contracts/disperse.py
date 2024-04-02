from eth_typing import ChecksumAddress
from web3.contract.async_contract import AsyncContractFunction
from web3.types import Wei

from ._abi import DISPERSE_ABI
from ..contract import Contract


class Disperse(Contract):
    DEFAULT_ABI = DISPERSE_ABI
    DEFAULT_ADDRESS = "0xD152f549545093347A162Dce210e7293f1452150"

    def disperse_ether(
            self,
            recipients: list[ChecksumAddress | str],
            values: list[Wei | int],
    ) -> AsyncContractFunction:
        """
        disperseEther(address[] recipients, uint256[] values)
        """
        return self.functions.disperseEther(recipients, values)
