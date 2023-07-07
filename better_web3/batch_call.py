import time
from typing import Iterable, Any
from typing import TYPE_CHECKING

import eth_abi
from eth_abi.exceptions import DecodingError
from eth_typing import ChecksumAddress, HexStr, Address, Hash32
from hexbytes import HexBytes
from web3._utils.abi import map_abi_data
from web3._utils.method_formatters import (
    block_formatter,
    receipt_formatter,
    transaction_result_formatter,
)
from web3._utils.normalizers import BASE_RETURN_NORMALIZERS
from web3.contract.contract import ContractFunction
from web3.types import (
    BlockData,
    BlockIdentifier,
    TxData,
    TxParams,
    TxReceipt,
    Wei,
)

from .utils import chunks
from .utils.eth import hex_block_identifier

if TYPE_CHECKING:
    from .chain import Chain


def build_payload(index: int, method: str, params: list) -> dict:
    return {"id": index, "jsonrpc": "2.0", "method": method, "params": params}


def process_results(results, *, raise_exceptions: bool = True) -> Iterable:
    """Process result from the batch request."""
    if isinstance(results, dict) and "error" in results:
        raise JSONRPCException(results["error"]["code"], results["error"]["message"])

    # Nodes like Erigon send back results out of order
    for result in sorted(results, key=lambda x: x["id"]):
        if "error" in result:
            e = JSONRPCException(result["error"]["code"], result["error"]["message"])
            if raise_exceptions:
                raise e
            else:
                yield e
        else:
            yield result["result"]


def decode_and_normalize_eth_call_result(result, output_type):
    """Decodes and normalizes a result based on the output_type."""
    decoded_values = eth_abi.decode(output_type, HexBytes(result))
    normalized_data = map_abi_data(BASE_RETURN_NORMALIZERS, output_type, decoded_values)
    return normalized_data[0] if len(normalized_data) == 1 else normalized_data


def process_eth_call_results(
        results,
        output_types,
        *,
        raise_exceptions: bool = True,
) -> Iterable:
    for result, output_type in zip(results, output_types):
        try:
            yield decode_and_normalize_eth_call_result(result, output_type)
        except (DecodingError, OverflowError):
            e = JSONRPCException(result["error"]["code"], f'DecodingError, cannot decode')
            if raise_exceptions:
                raise e
            else:
                yield e


class JSONRPCException(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message
        super().__init__(f'(code {self.code}) {self.message}')


class Manager:
    def __init__(self, chain: "Chain"):
        self.chain = chain
        self.rpc = chain.rpc
        self.w3 = chain.w3
        self.slow_w3 = chain.slow_w3
        self.http_session = chain.http_session
        self.timeout = chain.timeout
        self.slow_timeout = chain.slow_timeout


class BatchCallManager(Manager):

    def __init__(
            self,
            chain: "Chain",
            batch_request_size: int = 500,
            batch_request_delay: int = 1,
    ):
        super().__init__(chain)
        self.batch_request_size = batch_request_size
        self.batch_request_delay = batch_request_delay

    def request(
            self,
            payloads: Iterable[dict],
            *,
            raise_exceptions: bool = True,
            batch_size: int = None,
            delay: int = None,
    ) -> Iterable[dict[str: dict, str: Any]]:
        if not payloads:
            return []

        batch_size = batch_size or self.batch_request_size
        delay = delay or self.batch_request_delay

        for chunk in chunks(payloads, batch_size):
            response = self.http_session.post(self.rpc, json=chunk, timeout=self.slow_timeout)
            results = response.json()
            for payload, response in zip(chunk, process_results(results, raise_exceptions=raise_exceptions)):
                result = {"payload": payload}
                if isinstance(response, JSONRPCException):
                    result["exception"] = response
                else:
                    result["result"] = response
                yield result
            time.sleep(delay)  # TODO Сделать это умнее

    def contract_request(
            self,
            contract_functions: Iterable[ContractFunction],
            block_identifier: BlockIdentifier = "latest",
            from_: ChecksumAddress | str = None,
            *,
            raise_exceptions: bool = True,
            batch_size: int = None,
            delay: int = None,
    ) -> Iterable[dict[str: ContractFunction, str: Any]]:
        if not contract_functions:
            return []

        block_identifier = hex_block_identifier(block_identifier)

        payloads = []
        output_types = []
        for i, contract_function in enumerate(contract_functions):
            if not contract_function.address:
                raise ValueError(
                    f"Missing address for batch_call in `{contract_function.fn_name}`: {contract_function}")

            data = contract_function.build_transaction({"gas": 0, "gasPrice": 0})["data"]
            tx_params = {"to": contract_function.address, "data": data}
            if from_: tx_params["from"] = from_
            payloads.append(build_payload(i, "eth_call", [tx_params, block_identifier]))

            output_type = [output["type"] for output in contract_function.abi["outputs"]]
            output_types.append(output_type)

            # fn_name = contract_function.fn_name  # For debugging purposes

        results = self.request(
            payloads,
            raise_exceptions=raise_exceptions,
            batch_size=batch_size,
            delay=delay,
        )
        results = process_eth_call_results(results, output_types, raise_exceptions=raise_exceptions)
        for contract_function, response in zip(contract_functions, results):
            result = {"contract_function": contract_function}
            if isinstance(response, JSONRPCException):
                result["exception"] = response
            else:
                result["result"] = response
            yield result

    ################################################################################
    # Batch request shortcuts
    ################################################################################

    def balances(
            self,
            addresses: Iterable[ChecksumAddress | str],
            block_identifier: BlockIdentifier = "latest",
            **kwargs,
    ) -> Iterable[dict[str: ChecksumAddress | str, str: Wei | JSONRPCException]]:
        if not addresses:
            return []

        payloads = [build_payload(i, "eth_getBalance", [address, hex_block_identifier(block_identifier)])
                    for i, address in enumerate(addresses)]
        balances = self.request(payloads, **kwargs)

        for address, response in zip(addresses, balances):
            balance_data = {"address": address}
            if "exception" in response:
                balance_data["exception"] = response["exception"]
            else:
                balance_data["balance"] = Wei(int(response["result"], 16))
            yield balance_data

    def txs(
            self,
            tx_hashes: Iterable[Hash32 | HexBytes | HexStr],
            **kwargs,
    ) -> Iterable[dict[str: Hash32 | HexBytes | HexStr, str: TxData | JSONRPCException]]:
        if not tx_hashes:
            return []

        payloads = [build_payload(i, "eth_getTransactionByHash", [HexBytes(tx_hash).hex()])
                    for i, tx_hash in enumerate(tx_hashes)]
        txs = self.request(payloads, **kwargs)

        for tx_hash, response in zip(tx_hashes, txs):
            tx_data = {"tx_hash": tx_hash}
            if "exception" in response:
                tx_data["exception"] = response["exception"]
            else:
                tx_data["tx"] = transaction_result_formatter(response["result"])
            yield tx_data

    def tx_receipts(
            self,
            tx_hashes: Iterable[Hash32 | HexBytes | HexStr],
            **kwargs,
    ) -> Iterable[dict[str: Hash32 | HexBytes | HexStr, str: TxReceipt | JSONRPCException]]:
        if not tx_hashes:
            return []

        payloads = [build_payload(i, "eth_getTransactionReceipt", [HexBytes(tx_hash).hex()])
                    for i, tx_hash in enumerate(tx_hashes)]
        tx_receipts = self.request(payloads, **kwargs)

        for tx_hash, response in zip(tx_hashes, tx_receipts):
            tx_receipt_data = {"tx_hash": tx_hash}
            if "exception" in response:
                tx_receipt_data["exception"] = response["exception"]
            else:
                tx_receipt_data["tx"] = receipt_formatter(response["result"])
            yield tx_receipt_data

    def blocks(
            self,
            block_identifiers: Iterable[BlockIdentifier],
            full_transactions: bool = False,
            **kwargs,
    ) -> Iterable[dict[str: BlockIdentifier, str: BlockData | None | JSONRPCException]]:
        if not block_identifiers:
            return []

        payloads = []
        for i, block_identifier in enumerate(block_identifiers):
            is_int = isinstance(block_identifier, int)
            method = "eth_getBlockByNumber" if is_int else "eth_getBlockByHash"
            block_identifier = block_identifier if is_int else hex_block_identifier(block_identifier)
            payloads.append(build_payload(i, method, [block_identifier, full_transactions]))

        blocks_data = self.request(payloads, **kwargs)

        for block_identifier, response in zip(block_identifiers, blocks_data):
            block_data = {"block_identifier": block_identifier}
            if "exception" in response:
                block_data["exception"] = response["exception"]
            else:
                if "extraData" in response["exception"]:
                    del block_data["extraData"]  # Remove extraData, raises some problems on parsing
                block_data["block"] = receipt_formatter(block_formatter(response["result"]))
            yield block_data
