from functools import wraps
from typing import (
    Any,
    Iterable,
    Optional,
    Sequence,
    Union,
    Callable,
)

import eth_abi
import requests
from eth_abi.exceptions import DecodingError
from eth_account.signers.local import LocalAccount
from eth_typing import BlockNumber, ChecksumAddress, HexStr, Address
from eth_utils import to_checksum_address
from hexbytes import HexBytes
from requests.adapters import HTTPAdapter
from web3 import HTTPProvider, Web3
from web3._utils.abi import map_abi_data
from web3._utils.method_formatters import (
    block_formatter,
    receipt_formatter,
    trace_list_result_formatter,
    transaction_result_formatter,
)
from web3._utils.normalizers import BASE_RETURN_NORMALIZERS
from web3.contract.contract import ContractFunction
from web3.exceptions import (
    BlockNotFound,
    TimeExhausted,
    TransactionNotFound,
    Web3Exception,
)
from web3.middleware import geth_poa_middleware
from web3.types import (
    BlockData,
    BlockIdentifier,
    BlockTrace,
    FilterParams,
    FilterTrace,
    Nonce,
    TxData,
    TxParams,
    TxReceipt,
    Wei,
)

from .contract import Contract, Multicall, ERC20, ERC721
from .enums import TxSpeed
from .exceptions import error_msg_to_exception, BatchCallFunctionFailed
from .explorer import Explorer
from .gas_station import GasStation
from .models import NativeToken
from .types import TxHash
from .utils import cache, chunks


def tx_with_exception_handling(func: Callable) -> Callable:
    """
    Parity / OpenEthereum
        - https://github.com/openethereum/openethereum/blob/main/rpc/src/v1/helpers/errors.rs
    Geth
        - https://github.com/ethereum/go-ethereum/blob/master/core/error.go
        - https://github.com/ethereum/go-ethereum/blob/master/core/tx_pool.go
    Comparison
        - https://gist.github.com/kunal365roy/3c37ac9d1c3aaf31140f7c5faa083932

    """

    @wraps(func)
    def with_exception_handling(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (Web3Exception, ValueError) as exc:
            str_exc = str(exc).lower()
            for reason, custom_exception in error_msg_to_exception.items():
                if reason.lower() in str_exc:
                    raise custom_exception(str(exc)) from exc
            raise exc

    return with_exception_handling


class Chain:
    def __init__(
            self,
            rpc: str,
            explorer: Explorer = None,
            gas_station: GasStation = None,
            native_token: NativeToken = None,
            multicall_v3_address: ChecksumAddress | str = None,
            use_poa_middleware: bool = True,
            provider_timeout: int = 15,
            slow_provider_timeout: int = 60,
            retry_count: int = 3,
            batch_request_max_size: int = 500,
    ):
        self._rpc = rpc
        self.explorer = explorer
        self.gas_station = gas_station
        self.native_token = native_token or NativeToken()

        self.http_session = self._prepare_http_session(retry_count)
        self.timeout = provider_timeout
        self.slow_timeout = slow_provider_timeout

        self.w3_provider = self._create_http_provider(provider_timeout)
        self.w3_slow_provider = self._create_http_provider(slow_provider_timeout)

        self.w3 = Web3(provider=self.w3_provider)
        self.slow_w3 = Web3(provider=self.w3_slow_provider)
        self.batch_request_max_size = batch_request_max_size

        self.multicall = Multicall(chain=self, address=multicall_v3_address)

        if use_poa_middleware:
            self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
            self.slow_w3.middleware_onion.inject(geth_poa_middleware, layer=0)

    def _create_http_provider(self, timeout: int) -> HTTPProvider:
        return HTTPProvider(
            self._rpc,
            request_kwargs={"timeout": timeout},
            session=self.http_session,
        )

    def __repr__(self):
        return f"Chain({self.w3.provider})"

    @staticmethod
    def _prepare_http_session(retry_count: int) -> requests.Session:
        """
        Prepare http session with custom pooling. See:
        https://urllib3.readthedocs.io/en/stable/advanced-usage.html
        https://2.python-requests.org/en/latest/api/#requests.adapters.HTTPAdapter
        https://web3py.readthedocs.io/en/stable/providers.html#httpprovider
        """
        session = requests.Session()
        adapter = HTTPAdapter(
            pool_connections=1,  # Doing all the connections to the same url
            pool_maxsize=100,  # Number of concurrent connections
            max_retries=retry_count,  # Nodes are not very responsive some times
            pool_block=False,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    @property
    def rpc(self):
        return self._rpc

    ################################################################################
    # Contract creation shortcuts
    ################################################################################

    def contract(self, address, abi) -> Contract:
        return Contract(self, address, abi)

    def erc20(self, address) -> ERC20:
        return ERC20(self, address)

    def erc721(self, address) -> ERC721:
        return ERC721(self, address)

    ################################################################################
    # Chain info
    ################################################################################

    def get_current_block_number(self) -> BlockNumber:
        return self.w3.eth.block_number

    @property
    @cache
    def chain_id(self) -> int:
        return self.w3.eth.chain_id

    @property
    @cache
    def client_version(self) -> str:
        return self.w3.client_version

    @property
    @cache
    def is_eip1559_supported(self) -> bool:
        """
        :return: True if EIP1559 is supported by the node, False otherwise
        """
        last_block = self.get_block("latest")
        return True if "baseFeePerGas" in last_block else False

    ################################################################################
    # Запрос цены газа
    ################################################################################

    def get_gas_price(self) -> Wei:
        return self.w3.eth.gas_price

    def estimate_eip1559_fees(self, tx_speed: TxSpeed = TxSpeed.NORMAL) -> tuple[int, int]:
        """
        Check https://github.com/ethereum/execution-apis/blob/main/src/eth/fee_market.yaml

        :return: Tuple[maxFeePerGas, MaxPriorityFeePerGas]
        :raises: ValueError if not supported on the network
        """
        tx_speed_percentiles = {
            TxSpeed.SLOWEST: 0,
            TxSpeed.VERY_SLOW: 10,
            TxSpeed.SLOW: 25,
            TxSpeed.NORMAL: 50,
            TxSpeed.FAST: 75,
            TxSpeed.VERY_FAST: 90,
            TxSpeed.FASTEST: 100
        }
        percentile = tx_speed_percentiles[tx_speed]
        result = self.w3.eth.fee_history(1, "latest", reward_percentiles=[percentile])
        # Get next block `base_fee_per_gas`
        base_fee_per_gas = result["baseFeePerGas"][-1]
        max_priority_fee_per_gas = result["reward"][0][0]
        max_fee_per_gas = base_fee_per_gas + max_priority_fee_per_gas
        return max_fee_per_gas, max_priority_fee_per_gas

    ################################################################################
    # Работа с транзакциями
    ################################################################################

    def _build_tx_base_params(
            self,
            gas: int = None,
            from_: Address | ChecksumAddress | str = None,
            to: Address | ChecksumAddress | str = None,
            nonce: Nonce = None,
            value: Wei = None,
            *,
            tx_params: TxParams = dict(),
    ) -> TxParams:
        tx_params = tx_params.copy()

        tx_params["chainId"] = self.chain_id

        if gas is not None:
            tx_params["gas"] = gas
        if from_ is not None:
            tx_params["from"] = from_
        if to is not None:
            tx_params["to"] = to
        if value is not None:
            tx_params["value"] = value

        if nonce is not None:
            tx_params["nonce"] = nonce
        elif from_ is not None:
            tx_params["nonce"] = self.get_nonce(from_)

        return tx_params

    def _build_tx_fee_params(
            self,
            # legacy pricing
            gas_price: Wei = None,
            # dynamic fee pricing
            max_fee_per_gas: Wei = None,
            max_priority_fee_per_gas: Wei = None,
            tx_speed: TxSpeed = TxSpeed.NORMAL,
            *,
            tx_params: TxParams = dict(),
    ) -> TxParams:
        tx_params = tx_params.copy()

        if gas_price is not None:
            tx_params["gasPrice"] = gas_price
        elif max_fee_per_gas is not None:
            tx_params["maxFeePerGas"] = max_fee_per_gas
        if max_priority_fee_per_gas is not None:
            tx_params["maxPriorityFeePerGas"] = max_priority_fee_per_gas
        # TODO изменить логику
        if gas_price is None and max_fee_per_gas is None and max_priority_fee_per_gas is None:
            if self.is_eip1559_supported:
                max_fee_per_gas, max_priority_fee_per_gas = self.estimate_eip1559_fees(tx_speed)
                tx_params["maxFeePerGas"] = max_fee_per_gas
                tx_params["maxPriorityFeePerGas"] = max_priority_fee_per_gas
            else:
                tx_params["gasPrice"] = self.get_gas_price()

        return tx_params

    def build_tx(
            self,
            contract_function: ContractFunction,
            gas: int = None,
            from_: Address | ChecksumAddress | str = None,
            to: Address | ChecksumAddress | str = None,
            nonce: Nonce = None,
            value: Wei = None,
            # legacy pricing
            gas_price: Wei = None,
            # dynamic fee pricing
            max_fee_per_gas: Wei = None,
            max_priority_fee_per_gas: Wei = None,
            tx_speed: TxSpeed = TxSpeed.NORMAL,
    ) -> TxParams:
        """
        Builds and sets the transaction parameters including gas parameters.

        Args:
            contract_function (ContractFunction): The contract function.
            gas (int): The gas limit.
            from_ (ChecksumAddress): The address from which the transaction is sent.
            to (ChecksumAddress): Address to.
            nonce (Nonce): The transaction nonce.
            value (Wei): Value to send.
            gas_price (Wei): The gas price (legacy).
            max_fee_per_gas (Wei): The maximum fee per gas.
            max_priority_fee_per_gas (Wei): The maximum priority fee per gas.
            tx_speed (TxSpeed): The transaction speed.

        Returns:
            TxParams: Transaction parameters.
        """
        tx_params = self._build_tx_base_params(gas, from_, to, nonce, value)
        gas = contract_function.estimate_gas(tx_params)
        tx_params = self._build_tx_base_params(gas, tx_params=tx_params)
        tx_params = self._build_tx_fee_params(
            gas_price, max_fee_per_gas, max_priority_fee_per_gas, tx_speed, tx_params=tx_params)
        return contract_function.build_transaction(tx_params)

    def sign_and_send_tx(
            self, account: LocalAccount, transaction_dict: TxParams
    ) -> HexStr:
        signed_tx = account.sign_transaction(transaction_dict)
        tx_hash = self._send_raw_tx(signed_tx.rawTransaction)
        return tx_hash.hex()

    @tx_with_exception_handling
    def _send_tx(self, transaction_dict: TxParams) -> HexBytes:
        return self.w3.eth.send_transaction(transaction_dict)

    @tx_with_exception_handling
    def _send_raw_tx(self, raw_transaction: bytes | HexStr) -> HexBytes:
        return self.w3.eth.send_raw_transaction(bytes(raw_transaction))

    ################################################################################
    # Запрос данных
    ################################################################################

    def is_contract(self, contract_address: ChecksumAddress) -> bool:
        return bool(self.w3.eth.get_code(contract_address))

    def get_nonce(self, address: ChecksumAddress) -> int:
        return self.w3.eth.get_transaction_count(address)

    def get_balance(
            self,
            address: ChecksumAddress,
            block_identifier: Optional[BlockIdentifier] = None,
    ):
        address = to_checksum_address(address)
        return self.w3.eth.get_balance(address, block_identifier)

    def get_balances(
            self,
            addresses: Iterable[ChecksumAddress],
            block_identifier: Optional[BlockIdentifier] = None,
    ) -> dict[str: Wei]:
        if not addresses:
            return []
        if block_identifier is not None:
            block_identifier = self._parse_block_identifier(block_identifier)
        else:
            block_identifier = "latest"
        payload = [
            {
                "id": i,
                "jsonrpc": "2.0",
                "method": "eth_getBalance",
                "params": [address, block_identifier],
            }
            for i, address in enumerate(addresses)
        ]
        balances = self.raw_batch_request(payload)
        return {address: int(balance, 16) for address, balance in zip(addresses, balances)}

    def get_tx(self, tx_hash: TxHash) -> Optional[TxData]:
        try:
            return self.w3.eth.get_transaction(tx_hash)
        except TransactionNotFound:
            return None

    def get_txs(self, tx_hashes: list[TxHash]) -> list[Optional[TxData]]:
        if not tx_hashes:
            return []
        payload = [
            {
                "id": i,
                "jsonrpc": "2.0",
                "method": "eth_getTransactionByHash",
                "params": [HexBytes(tx_hash).hex()],
            }
            for i, tx_hash in enumerate(tx_hashes)
        ]
        results = self.raw_batch_request(payload)
        return [
            transaction_result_formatter(raw_tx) if raw_tx else None
            for raw_tx in results
        ]

    def get_tx_receipt(self, tx_hash: TxHash) -> TxReceipt | None:
        try:
            tx_receipt = self.w3.eth.get_transaction_receipt(tx_hash)
            return (
                tx_receipt
                if tx_receipt and tx_receipt["blockNumber"] is not None
                else None
            )
        except TransactionNotFound:
            return None

    def wait_for_tx_receipt(
            self, tx_hash: TxHash, timeout: float = 120, poll_latency: float = 0.1
    ) -> TxReceipt | None:
        try:
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout, poll_latency)
            return (
                tx_receipt
                if tx_receipt and tx_receipt["blockNumber"] is not None
                else None
            )
        except (TimeExhausted, TransactionNotFound):
            return None

    def get_tx_receipts(
            self,
            tx_hashes: Iterable[TxHash],
    ) -> dict[TxHash: TxReceipt | None]:
        """
        Retrieves transaction receipts for the given transaction hashes.

        Args:
            tx_hashes (Iterable[TxHash]): Iterable of transaction hashes.

        Returns:
            dict[TxHash, Optional[TxReceipt]]: A dictionary where the keys are transaction hashes (TxHash)
            and the values are the corresponding transaction receipts (TxReceipt) or None.
        """
        if not tx_hashes:
            return {}
        payload = [
            {
                "id": i,
                "jsonrpc": "2.0",
                "method": "eth_getTransactionReceipt",
                "params": [HexBytes(tx_hash).hex()],
            }
            for i, tx_hash in enumerate(tx_hashes)
        ]
        results = self.raw_batch_request(payload)
        receipts = {}
        for tx_hash, tx_receipt in zip(tx_hashes, results):
            if tx_receipt and tx_receipt["blockNumber"] is not None:
                receipts[tx_hash] = receipt_formatter(tx_receipt)
            else:
                receipts[tx_hash] = None
        return receipts

    def get_block(
            self, block_identifier: BlockIdentifier, full_transactions: bool = False
    ) -> Optional[BlockData]:
        try:
            return self.w3.eth.get_block(
                block_identifier, full_transactions=full_transactions
            )
        except BlockNotFound:
            return None

    @staticmethod
    def _parse_block_identifier(block_identifier: BlockIdentifier) -> str:
        if isinstance(block_identifier, int):
            return hex(block_identifier)
        elif isinstance(block_identifier, bytes):
            return HexBytes(block_identifier).hex()
        else:
            return block_identifier

    def get_blocks(
            self,
            block_identifiers: Iterable[BlockIdentifier],
            full_transactions: bool = False,
    ) -> list[Optional[BlockData]]:
        if not block_identifiers:
            return []
        payload = [
            {
                "id": i,
                "jsonrpc": "2.0",
                "method": "eth_getBlockByNumber"
                if isinstance(block_identifier, int)
                else "eth_getBlockByHash",
                "params": [
                    self._parse_block_identifier(block_identifier),
                    full_transactions,
                ],
            }
            for i, block_identifier in enumerate(block_identifiers)
        ]
        results = self.raw_batch_request(payload)
        blocks = []
        for raw_block in results:
            if raw_block:
                if "extraData" in raw_block:
                    del raw_block[
                        "extraData"
                    ]  # Remove extraData, raises some problems on parsing
                blocks.append(block_formatter(raw_block))
            else:
                blocks.append(None)
        return blocks

    def check_tx_with_confirmations(self, tx_hash: TxHash, confirmations: int) -> bool:
        """
        Check the transaction hash and ensure it has the required number of confirmations.

        Args:
            tx_hash (TxHash): Hash of the transaction.
            confirmations (int): Minimum number of confirmations required.

        Returns:
            bool: True if the transaction was mined with the specified number of confirmations,
                  False otherwise.
        """
        tx_receipt = self.get_tx_receipt(tx_hash)

        if not tx_receipt or tx_receipt["blockNumber"] is None:
            # If `tx_receipt` exists but `blockNumber` is `None`,
            # the transaction is still pending (only for Parity).
            return False
        else:
            block_number = self.w3.eth.block_number
            confirmations_count = block_number - tx_receipt["blockNumber"]

            return confirmations_count >= confirmations

    ################################################################################
    # Batch call and multicall
    ################################################################################

    def _custom_batch_call(
            self,
            payloads: Iterable[dict[str, Any]],
            raise_exception: bool = True,
            block_identifier: Optional[BlockIdentifier] = "latest",
            batch_size: Optional[int] = None,
    ) -> list[Optional[Any]]:
        """
        Perform batch requests for multiple contract calls (`eth_call`).

        Args:
            payloads (Iterable[dict[str, Any]]): Iterable of dictionaries with at least the following keys:
                - 'data': Hex string representing the data for the contract call.
                - 'output_type': Solidity output type.
                - 'to': Checksummed address of the contract.
                'from' (optional): The sender's address for the contract call.
                'fn_name' (optional): Function name for debugging purposes.

            raise_exception (bool): If False, exceptions will not be raised in case of any problem,
                and instead `None` will be returned as the value. Default is True.

            block_identifier (Optional[BlockIdentifier]): The block identifier to use for the contract call.
                It can be an integer block number or the string "latest". Default is "latest".

            batch_size (Optional[int]): If the length of `payloads` is larger than `batch_size`, it will be split
                into smaller chunks before sending to the server. Default is None.

        Returns:
            list[Optional[Any]]: List containing the ABI decoded return values.

        Raises:
            ValueError: If `raise_exception` is True and there is an error during the batch call.

        """
        if not payloads:
            return []

        queries = []
        for i, payload in enumerate(payloads):
            required_keys = ["data", "to", "output_type"]
            missing_keys = [key for key in required_keys if key not in payload]
            assert not missing_keys, f"Missing keys in payload: {missing_keys}"

            query_params = {"to": payload["to"], "data": payload["data"]}
            if "from" in payload:
                query_params["from"] = payload["from"]

            queries.append(
                {
                    "id": i,
                    "jsonrpc": "2.0",
                    "method": "eth_call",
                    "params": [
                        query_params,
                        hex(block_identifier)
                        if isinstance(block_identifier, int)
                        else block_identifier,
                    ],
                }
            )

        batch_size = batch_size or self.batch_request_max_size
        all_results = []
        for chunk in chunks(queries, batch_size):
            response = self.http_session.post(
                self.rpc, json=chunk, timeout=self.slow_timeout
            )
            if not response.ok:
                raise ConnectionError(f"Error connecting to {self.rpc}: {response.text}")

            results = response.json()

            # If there's an error, some nodes return a JSON instead of a list
            if isinstance(results, dict) and "error" in results:
                raise ValueError(f"Batch call custom problem with payload={chunk}, result={results})")

            all_results.extend(results)

        return_values = []
        errors = []
        for payload, result in zip(
                payloads, sorted(all_results, key=lambda x: x["id"])
        ):
            if "error" in result:
                fn_name = payload.get("fn_name", HexBytes(payload["data"]).hex())
                errors.append(f'`{fn_name}`: {result["error"]}')
                return_values.append(None)
            else:
                output_type = payload["output_type"]
                try:
                    decoded_values = eth_abi.decode(output_type, HexBytes(result["result"]))
                    normalized_data = map_abi_data(
                        BASE_RETURN_NORMALIZERS, output_type, decoded_values
                    )
                    return_values.append(normalized_data[0] if len(normalized_data) == 1 else normalized_data)
                except (DecodingError, OverflowError):
                    fn_name = payload.get("fn_name", HexBytes(payload["data"]).hex())
                    errors.append(f"`{fn_name}`: DecodingError, cannot decode")
                    return_values.append(None)

        if errors and raise_exception:
            raise BatchCallFunctionFailed(f"Errors returned {errors}")
        else:
            return return_values

    def _batch_call(
            self,
            contract_functions: Iterable[ContractFunction],
            from_address: Optional[ChecksumAddress] = None,
            raise_exception: bool = True,
            block_identifier: Optional[BlockIdentifier] = "latest",
    ) -> list[Optional[Any]]:
        """
        Do batch requests of multiple contract calls

        :param contract_functions: Iterable of contract functions using web3.py contracts. For instance, a valid
            argument would be [erc20_contract.functions.balanceOf(address), erc20_contract.functions.decimals()]
        :param from_address: Use this address as `from` in every call if provided
        :param block_identifier: `latest` by default
        :param raise_exception: If False, exception will not be raised if there's any problem and instead `None` will
            be returned as the value.
        :return: List with the ABI decoded return values
        """
        if not contract_functions:
            return []
        payloads = []
        params: TxParams = {"gas": Wei(0), "gasPrice": Wei(0)}
        for _, contract_function in enumerate(contract_functions):
            if not contract_function.address:
                raise ValueError(
                    f"Missing address for batch_call in `{contract_function.fn_name}`"
                )

            payload = {
                "to": contract_function.address,
                "data": contract_function.build_transaction(params)["data"],
                "output_type": [
                    output["type"] for output in contract_function.abi["outputs"]
                ],
                "fn_name": contract_function.fn_name,  # For debugging purposes
            }
            if from_address:
                payload["from"] = from_address
            payloads.append(payload)

        return self._custom_batch_call(
            payloads, raise_exception=raise_exception, block_identifier=block_identifier
        )

    def raw_batch_request(
            self,
            payload: list[dict[str, Any]],
            batch_size: Optional[int] = None
    ) -> Iterable[Optional[dict[str, Any]]]:
        """
        Perform a raw batch JSON RPC call.

        Args:
            payload (list[dict[str, Any]]): Batch request payload. Make sure all provided `ids` inside the payload are different.
            batch_size (Optional[int]): If the length of `payload` is larger than `batch_size`, it will be split into smaller
                chunks before sending to the server. Default is None.

        Yields:
            Optional[dict[str, Any]]: Iterable of batch request results. Each result is a dictionary.

        Raises:
            ValueError: If there is a problem during the raw batch request.

        """
        batch_size = batch_size or self.batch_request_max_size

        all_results = []
        for chunk in chunks(payload, batch_size):
            response = self.http_session.post(
                self.rpc, json=chunk, timeout=self.slow_timeout
            )

            if not response.ok:
                error_message = (f"Problem doing raw batch request with payload={chunk}"
                                 f"\nstatus_code={response.status_code} result={response.content}")
                if response.status_code == 521:
                    error_message += "\nTry to change provider (rpc)"
                raise ValueError(error_message)

            results = response.json()

            # If there's an error, some nodes return a JSON instead of a list
            if isinstance(results, dict) and "error" in results:
                raise ValueError(f"Batch request problem with payload={chunk}, result={results})")

            all_results.extend(results)

        # Nodes like Erigon send back results out of order
        for query, result in zip(payload, sorted(all_results, key=lambda x: x["id"])):
            if "result" not in result:
                raise ValueError(f"Problem with payload={query} result={result}")
            yield result["result"]

    def batch_call(
            self,
            contract_functions: list[ContractFunction],
            from_address: Optional[ChecksumAddress] = None,
            raise_exception: bool = True,
            use_multicall: bool = True,
            block_identifier: Optional[BlockIdentifier] = "latest"
    ) -> list[Optional[Union[bytes, Any]]]:
        """
        Call multiple functions and return the results.

        Args:
            contract_functions (list[ContractFunction]): The list of contract functions to call.
            from_address (Optional[ChecksumAddress]): The address from which the calls are made.
                Only available when `Multicall` is not used.
            raise_exception (bool): If True, raise `BatchCallException` if one of the calls fails.
            use_multicall (bool): If False, ignore multicall and always use batch calls to get the results
                (less optimal). If True, a more optimal way will be tried.
            block_identifier (Optional[BlockIdentifier]): The identifier of the block to query.
                Defaults to "latest".

        Returns:
            list[Optional[Union[bytes, Any]]]: A list of elements decoded to their respective types.
                If decoding is not possible, None is returned.
                If a revert error is returned and `raise_exception` is False, bytes are returned.

        Raises:
            BatchCallException: If `raise_exception` is True and one of the calls fails.
        """
        results = []

        if not contract_functions:
            return results

        if self.multicall and use_multicall:
            results = [
                result.return_data_decoded
                for result in self.multicall.try_aggregate(
                    contract_functions,
                    require_success=raise_exception,
                    block_identifier=block_identifier,
                )
            ]
        else:
            results = self._batch_call(
                contract_functions,
                from_address=from_address,
                raise_exception=raise_exception,
                block_identifier=block_identifier,
            )

        return results
