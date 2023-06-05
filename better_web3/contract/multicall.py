"""More about MulticallV3: https://github.com/mds1/multicall
"""
from dataclasses import dataclass
from typing import Any, List, Optional, Sequence, Tuple

import eth_abi
from eth_abi.exceptions import DecodingError
from eth_typing import BlockIdentifier, BlockNumber, ChecksumAddress
from hexbytes import HexBytes
from web3._utils.abi import map_abi_data
from web3._utils.normalizers import BASE_RETURN_NORMALIZERS
from web3.contract.contract import ContractFunction
from web3.exceptions import ContractLogicError

from ..exceptions import BatchCallFunctionFailed
from .abi import MULTICALL_V3_ABI
from .contract import Contract

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..chain import Chain


MULTICALL_V3_ADDRESS = "0xcA11bde05977b3631167028862bE2a173976CA11"


@dataclass
class MulticallResult:
    success: bool
    return_data: Optional[bytes]


@dataclass
class MulticallDecodedResult:
    success: bool
    return_data_decoded: Optional[Any]


class Multicall(Contract):
    def __init__(
        self,
        chain: "Chain",
        address: Optional[ChecksumAddress | str] = None,
        abi=None,
    ):
        address = address or MULTICALL_V3_ADDRESS
        abi = abi or MULTICALL_V3_ABI
        super().__init__(chain, address, abi)

    @staticmethod
    def _build_payload(
        contract_functions: Sequence[ContractFunction],
    ) -> tuple[list[tuple[ChecksumAddress, bytes]], list[list[Any]]]:
        targets_with_data = []
        output_types = []
        for contract_function in contract_functions:
            targets_with_data.append(
                (
                    contract_function.address,
                    HexBytes(contract_function._encode_transaction_data()),
                )
            )
            output_types.append(
                [output["type"] for output in contract_function.abi["outputs"]]
            )

        return targets_with_data, output_types

    @staticmethod
    def _decode_data(output_type: Sequence[str], data: bytes) -> Optional[Any]:
        """

        :param output_type:
        :param data:
        :return:
        :raises: DecodingError
        """
        if data:
            try:
                decoded_values = eth_abi.decode(output_type, data)
                normalized_data = map_abi_data(
                    BASE_RETURN_NORMALIZERS, output_type, decoded_values
                )
                if len(normalized_data) == 1:
                    return normalized_data[0]
                else:
                    return normalized_data
            except DecodingError:
                print(
                    "Cannot decode %s using output-type %s", data, output_type
                )
                return data

    def _aggregate(
        self,
        targets_with_data: Sequence[tuple[ChecksumAddress, bytes]],
        block_identifier: Optional[BlockIdentifier] = "latest",
    ) -> tuple[BlockNumber, list[Optional[Any]]]:
        """

        :param targets_with_data: List of target `addresses` and `data` to be called in each Contract
        :param block_identifier:
        :return:
        :raises: BatchCallFunctionFailed
        """
        aggregate_parameter = [
            {"target": target, "callData": data} for target, data in targets_with_data
        ]
        try:
            return self.contract.functions.aggregate(aggregate_parameter).call(
                block_identifier=block_identifier
            )
        except (ContractLogicError, OverflowError):
            raise BatchCallFunctionFailed

    def aggregate(
        self,
        contract_functions: Sequence[ContractFunction],
        block_identifier: Optional[BlockIdentifier] = "latest",
    ) -> Tuple[BlockNumber, List[Optional[Any]]]:
        """
        Calls aggregate on MakerDAO's Multicall contract. If a function called raises an error execution is stopped

        :param contract_functions:
        :param block_identifier:
        :return: A tuple with the ``blockNumber`` and a list with the decoded return values
        :raises: BatchCallFunctionFailed
        """
        targets_with_data, output_types = self._build_payload(contract_functions)
        block_number, results = self._aggregate(
            targets_with_data, block_identifier=block_identifier
        )
        decoded_results = [
            self._decode_data(output_type, data)
            for output_type, data in zip(output_types, results)
        ]
        return block_number, decoded_results

    def _try_aggregate(
        self,
        targets_with_data: Sequence[Tuple[ChecksumAddress, bytes]],
        require_success: bool = False,
        block_identifier: Optional[BlockIdentifier] = "latest",
    ) -> List[MulticallResult]:
        """
        Calls ``try_aggregate`` on MakerDAO's Multicall contract.

        :param targets_with_data:
        :param require_success: If ``True``, an exception in any of the functions will stop the execution. Also, an
            invalid decoded value will stop the execution
        :param block_identifier:
        :return: A list with the decoded return values
        """

        aggregate_parameter = [
            {"target": target, "callData": data} for target, data in targets_with_data
        ]
        try:
            result = self.functions.tryAggregate(
                require_success, aggregate_parameter
            ).call(block_identifier=block_identifier)

            if require_success and b"" in (data for _, data in result):
                # `b''` values are decoding errors/missing contracts/missing functions
                raise BatchCallFunctionFailed

            return [
                MulticallResult(success, data if data else None)
                for success, data in result
            ]
        except (ContractLogicError, OverflowError, ValueError):
            raise BatchCallFunctionFailed

    def try_aggregate(
        self,
        contract_functions: Sequence[ContractFunction],
        require_success: bool = False,
        block_identifier: Optional[BlockIdentifier] = "latest",
    ) -> List[MulticallDecodedResult]:
        """
        Calls ``try_aggregate`` on MakerDAO's Multicall contract.

        :param contract_functions:
        :param require_success: If ``True``, an exception in any of the functions will stop the execution
        :param block_identifier:
        :return: A list with the decoded return values
        """
        targets_with_data, output_types = self._build_payload(contract_functions)
        results = self._try_aggregate(
            targets_with_data,
            require_success=require_success,
            block_identifier=block_identifier,
        )
        return [
            MulticallDecodedResult(
                multicall_result.success,
                self._decode_data(output_type, multicall_result.return_data)
                if multicall_result.success
                else multicall_result.return_data,
            )
            for output_type, multicall_result in zip(output_types, results)
        ]
