"""
More about MulticallV3: https://github.com/mds1/multicall
"""

from dataclasses import dataclass
from typing import Any, Sequence

import eth_abi
from eth_abi.exceptions import DecodingError
from eth_typing import BlockIdentifier, BlockNumber, ChecksumAddress
from hexbytes import HexBytes
from web3._utils.abi import map_abi_data
from web3._utils.normalizers import BASE_RETURN_NORMALIZERS
from web3.contract.async_contract import AsyncContractFunction
from web3.exceptions import ContractLogicError

from ._abi import MULTICALL_V3_ABI
from ..contract import Contract


@dataclass
class MulticallResult:
    success: bool
    return_data: bytes | None


@dataclass
class MulticallDecodedResult:
    success: bool
    return_data_decoded: Any | None


class MulticallFailed(Exception):
    pass


class Multicall(Contract):
    DEFAULT_ABI = MULTICALL_V3_ABI
    DEFAULT_ADDRESS = "0xcA11bde05977b3631167028862bE2a173976CA11"

    @staticmethod
    def _build_payload(
        contract_functions: Sequence[AsyncContractFunction],
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
    def _decode_data(output_type: Sequence[str], data: bytes) -> Any | None:
        if not data:
            return

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

    async def _aggregate(
        self,
        targets_with_data: Sequence[tuple[ChecksumAddress, bytes]],
        block_identifier: BlockIdentifier = "latest",
    ) -> tuple[BlockNumber, list[Any | None]]:
        """
        :param targets_with_data: List of target `addresses` and `data` to be called in each Contract
        """
        aggregate_parameter = [
            {"target": target, "callData": data} for target, data in targets_with_data
        ]
        try:
            return await self.contract.functions.aggregate(aggregate_parameter).call(
                block_identifier=block_identifier
            )
        except (ContractLogicError, OverflowError):
            raise MulticallFailed

    async def aggregate(
        self,
        contract_functions: Sequence[AsyncContractFunction],
        block_identifier: BlockIdentifier = "latest",
    ) -> tuple[BlockNumber, list[Any | None]]:
        targets_with_data, output_types = self._build_payload(contract_functions)
        block_number, results = await self._aggregate(
            targets_with_data, block_identifier=block_identifier
        )
        decoded_results = [
            self._decode_data(output_type, data)
            for output_type, data in zip(output_types, results)
        ]
        return block_number, decoded_results

    async def _try_aggregate(
        self,
        targets_with_data: Sequence[tuple[ChecksumAddress, bytes]],
        require_success: bool = False,
        block_identifier: BlockIdentifier = "latest",
    ) -> list[MulticallResult]:
        aggregate_parameter = [
            {"target": target, "callData": data} for target, data in targets_with_data
        ]

        try:
            result = await self.functions.tryAggregate(
                require_success, aggregate_parameter
            ).call(block_identifier=block_identifier)

            if require_success and b"" in (data for _, data in result):
                # `b''` values are decoding errors/missing contracts/missing functions
                raise MulticallFailed

            return [
                MulticallResult(success, data if data else None)
                for success, data in result
            ]
        except (ContractLogicError, OverflowError, ValueError):
            raise MulticallFailed

    async def try_aggregate(
        self,
        contract_functions: Sequence[AsyncContractFunction],
        require_success: bool = False,
        block_identifier: BlockIdentifier = "latest",
    ) -> list[MulticallDecodedResult]:
        """
        Calls ``try_aggregate`` on MakerDAO's Multicall contract.

        :param require_success: If ``True``, an exception in any of the functions will stop the execution
        """
        targets_with_data, output_types = self._build_payload(contract_functions)
        results = await self._try_aggregate(
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
