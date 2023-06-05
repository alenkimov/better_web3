from enum import Enum
from functools import wraps
from typing import (
    Any,
    Iterable,
    Optional,
    Sequence,
    Union,
)

import eth_abi
import requests
from eth_abi.exceptions import DecodingError
from eth_account import Account
from eth_typing import BlockNumber, ChecksumAddress, HexStr, AnyAddress
from eth_utils import is_checksum_address, to_checksum_address
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
from web3.middleware import geth_poa_middleware, simple_cache_middleware
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


from .exceptions import (
    BatchCallFunctionFailed,
    ChainIdIsRequired,
    FromAddressNotFound,
    GasLimitExceeded,
    InsufficientFunds,
    InvalidNonce,
    NonceTooHigh,
    NonceTooLow,
    ReplacementTransactionUnderpriced,
    SenderAccountNotFoundInNode,
    TransactionAlreadyImported,
    TransactionGasPriceTooLow,
    TransactionQueueLimitReached,
    UnknownAccount,
)
from .explorer import Explorer
from .contract import Contract, Multicall, ERC20, ERC721
from .typing import TxHash
from .utils import cache, chunks


NULL_ADDRESS: str = "0x" + "0" * 40
GAS_CALL_DATA_ZERO_BYTE = 4
GAS_CALL_DATA_BYTE = 16  # 68 before Istanbul


class TxSpeed(Enum):
    SLOWEST = 0
    VERY_SLOW = 1
    SLOW = 2
    NORMAL = 3
    FAST = 4
    VERY_FAST = 5
    FASTEST = 6


def tx_with_exception_handling(func):
    """
    Parity / OpenEthereum
        - https://github.com/openethereum/openethereum/blob/main/rpc/src/v1/helpers/errors.rs
    Geth
        - https://github.com/ethereum/go-ethereum/blob/master/core/error.go
        - https://github.com/ethereum/go-ethereum/blob/master/core/tx_pool.go
    Comparison
        - https://gist.github.com/kunal365roy/3c37ac9d1c3aaf31140f7c5faa083932

    :param func:
    :return:
    """
    error_with_exception: dict[str, Exception] = {
        "EIP-155": ChainIdIsRequired,
        "Transaction with the same hash was already imported": TransactionAlreadyImported,
        # https://github.com/ethereum/go-ethereum/blob/eaccdba4ab310e3fb98edbc4b340b5e7c4d767fd/core/tx_pool.go#L72
        "replacement transaction underpriced": ReplacementTransactionUnderpriced,
        # https://github.com/openethereum/openethereum/blob/f1dc6821689c7f47d8fd07dfc0a2c5ad557b98ec/crates/rpc/src/v1/helpers/errors.rs#L374
        "There is another transaction with same nonce in the queue": ReplacementTransactionUnderpriced,
        "There are too many transactions in the queue. Your transaction was dropped due to limit. Try increasing "
        # https://github.com/openethereum/openethereum/blob/f1dc6821689c7f47d8fd07dfc0a2c5ad557b98ec/crates/rpc/src/v1/helpers/errors.rs#L380
        "the fee": TransactionQueueLimitReached,
        # https://github.com/ethereum/go-ethereum/blob/eaccdba4ab310e3fb98edbc4b340b5e7c4d767fd/core/tx_pool.go#L68
        "txpool is full": TransactionQueueLimitReached,
        # https://github.com/ethereum/go-ethereum/blob/eaccdba4ab310e3fb98edbc4b340b5e7c4d767fd/core/tx_pool.go#L64
        "transaction underpriced": TransactionGasPriceTooLow,
        # https://github.com/openethereum/openethereum/blob/f1dc6821689c7f47d8fd07dfc0a2c5ad557b98ec/crates/rpc/src/v1/helpers/errors.rs#L386
        "Transaction gas price is too low": TransactionGasPriceTooLow,
        "from not found": FromAddressNotFound,
        "correct nonce": InvalidNonce,
        # https://github.com/ethereum/go-ethereum/blob/bbfb1e4008a359a8b57ec654330c0e674623e52f/core/error.go#L46
        "nonce too low": NonceTooLow,
        # https://github.com/ethereum/go-ethereum/blob/bbfb1e4008a359a8b57ec654330c0e674623e52f/core/error.go#L46
        "nonce too high": NonceTooHigh,
        # https://github.com/openethereum/openethereum/blob/f1dc6821689c7f47d8fd07dfc0a2c5ad557b98ec/crates/rpc/src/v1/helpers/errors.rs#L389
        "insufficient funds": InsufficientFunds,
        "doesn't have enough funds": InsufficientFunds,
        "sender account not recognized": SenderAccountNotFoundInNode,
        "unknown account": UnknownAccount,
        # Geth
        "exceeds block gas limit": GasLimitExceeded,
        # https://github.com/openethereum/openethereum/blob/f1dc6821689c7f47d8fd07dfc0a2c5ad557b98ec/crates/rpc/src/v1/helpers/errors.rs#L392
        "exceeds current gas limit": GasLimitExceeded,
    }

    @wraps(func)
    def with_exception_handling(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (Web3Exception, ValueError) as exc:
            str_exc = str(exc).lower()
            for reason, custom_exception in error_with_exception.items():
                if reason.lower() in str_exc:
                    raise custom_exception(str(exc)) from exc
            raise exc

    return with_exception_handling


class Chain:
    def __init__(
            self,
            rpc: str,
            explorer: Optional[Explorer] = None,
            multicall_v3_address: Optional[AnyAddress or str] = None,
            use_caching_middleware: bool = True,
            use_poa_middleware: bool = True,
            provider_timeout: int = 15,
            slow_provider_timeout: int = 60,
            retry_count: int = 3,
            batch_request_max_size: int = 500,
    ):
        self.rpc = rpc
        self.http_session = self._prepare_http_session(retry_count)
        self.timeout = provider_timeout
        self.slow_timeout = slow_provider_timeout
        self.w3_provider = HTTPProvider(
            self.rpc,
            request_kwargs={"timeout": provider_timeout},
            session=self.http_session,
        )
        self.w3_slow_provider = HTTPProvider(
            self.rpc,
            request_kwargs={"timeout": slow_provider_timeout},
            session=self.http_session,
        )
        self.w3: Web3 = Web3(self.w3_provider)
        self.slow_w3: Web3 = Web3(self.w3_slow_provider)
        self.batch_request_max_size = batch_request_max_size

        self.explorer = explorer

        self.multicall = Multicall(self, multicall_v3_address)

        self.use_caching_middleware = use_caching_middleware
        self.use_poa_middleware = use_poa_middleware
        if self.use_poa_middleware:
            self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
            self.slow_w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        if self.use_caching_middleware:
            self.w3.middleware_onion.add(simple_cache_middleware)
            self.slow_w3.middleware_onion.add(simple_cache_middleware)

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

    ################################################################################
    # Contract creation shortcuts
    ################################################################################

    def contract(self, address, abi) -> Contract:
        return Contract(self, address, abi)

    def erc20(self, address) -> ERC20:
        return ERC20(self, address)

    def erc721(self, address) -> ERC721:
        return ERC721(self, address)

    def get_current_block_number(self) -> BlockNumber:
        return self.w3.eth.block_number

    ################################################################################
    # Chain info
    ################################################################################

    @cache
    def get_chain_id(self) -> int:
        """
        :return: ChainId returned by the RPC `eth_chainId` method. It should never change, so it's cached.
        """
        return int(self.w3.eth.chain_id)

    @cache
    def get_client_version(self) -> str:
        """
        :return: RPC version information
        """
        return self.w3.client_version

    @cache
    def is_eip1559_supported(self) -> bool:
        """
        :return: True if EIP1559 is supported by the node, False otherwise
        """
        try:
            self.w3.eth.fee_history(1, "latest", reward_percentiles=[50])
            return True
        except (Web3Exception, ValueError):
            return False

    ################################################################################
    # Helpers
    ################################################################################

    def get_nonce(
            self,
            address: ChecksumAddress,
            block_identifier: Optional[BlockIdentifier] = "latest",
    ):
        """
        Get nonce for account. `getTransactionCount` is the only method for what `pending` is currently working
        (Geth and Parity)
        """
        return self.w3.eth.get_transaction_count(address, block_identifier=block_identifier)

    def estimate_gas(
            self,
            to: str,
            from_: Optional[str] = None,
            value: Optional[int] = None,
            data: Optional[bytes | HexStr] = None,
            gas: Optional[int] = None,
            gas_price: Optional[int] = None,
            block_identifier: Optional[BlockIdentifier] = None,
    ) -> int:
        """
        Estimate gas calling `eth_estimateGas`

        :param block_identifier: Be careful, `Geth` does not support `pending` when estimating
        :return: Amount of gas needed for transaction
        :raises: ValueError
        """
        tx: TxParams = {"to": to}
        if from_:
            tx["from"] = from_
        if value:
            tx["value"] = value
        if data:
            tx["data"] = data
        if gas:
            tx["gas"] = gas
        if gas_price:
            tx["gasPrice"] = gas_price
        try:
            return self.w3.eth.estimate_gas(tx, block_identifier=block_identifier)
        except (Web3Exception, ValueError):
            if (
                    block_identifier is not None
            ):  # Geth does not support setting `block_identifier`
                return self.w3.eth.estimate_gas(tx, block_identifier=None)
            else:
                raise

    @staticmethod
    def estimate_data_gas(data: bytes):
        if isinstance(data, str):
            data = HexBytes(data)

        gas = 0
        for byte in data:
            if not byte:
                gas += GAS_CALL_DATA_ZERO_BYTE
            else:
                gas += GAS_CALL_DATA_BYTE
        return gas

    def estimate_fee_eip1559(
            self, tx_speed: TxSpeed = TxSpeed.NORMAL
    ) -> tuple[int, int]:
        """
        Check https://github.com/ethereum/execution-apis/blob/main/src/eth/fee_market.json#L15

        :return: Tuple[BaseFeePerGas, MaxPriorityFeePerGas]
        :raises: ValueError if not supported on the network
        """
        if tx_speed == TxSpeed.SLOWEST:
            percentile = 0
        elif tx_speed == TxSpeed.VERY_SLOW:
            percentile = 10
        elif tx_speed == TxSpeed.SLOW:
            percentile = 25
        elif tx_speed == TxSpeed.NORMAL:
            percentile = 50
        elif tx_speed == TxSpeed.FAST:
            percentile = 75
        elif tx_speed == TxSpeed.VERY_FAST:
            percentile = 90
        elif tx_speed == TxSpeed.FASTEST:
            percentile = 100

        result = self.w3.eth.fee_history(1, "latest", reward_percentiles=[percentile])
        # Get next block `base_fee_per_gas`
        base_fee_per_gas = result["baseFeePerGas"][-1]
        max_priority_fee_per_gas = result["reward"][0][0]
        return base_fee_per_gas, max_priority_fee_per_gas

    def set_eip1559_fees(
            self, tx: TxParams, tx_speed: TxSpeed = TxSpeed.NORMAL
    ) -> TxParams:
        """
        :return: TxParams in EIP1559 format
        :raises: ValueError if EIP1559 not supported
        """
        base_fee_per_gas, max_priority_fee_per_gas = self.estimate_fee_eip1559(tx_speed)
        tx = dict(tx)  # Don't modify provided tx
        if "gasPrice" in tx:
            del tx["gasPrice"]

        if "chainId" not in tx:
            tx["chainId"] = self.get_chain_id()

        tx["maxPriorityFeePerGas"] = max_priority_fee_per_gas
        tx["maxFeePerGas"] = base_fee_per_gas + max_priority_fee_per_gas
        return tx

    def get_balance(
            self,
            address: AnyAddress,
            block_identifier: Optional[BlockIdentifier] = None,
    ):
        address = to_checksum_address(address)
        return self.w3.eth.get_balance(address, block_identifier)

    def get_balances(
            self,
            addresses: Iterable[AnyAddress],
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
        # TODO Здесь преобразование не работает
        return {address: int(balance, 16) for address, balance in zip(addresses, balances)}

    def get_transaction(self, tx_hash: TxHash) -> Optional[TxData]:
        try:
            return self.w3.eth.get_transaction(tx_hash)
        except TransactionNotFound:
            return None

    def get_transactions(self, tx_hashes: list[TxHash]) -> list[Optional[TxData]]:
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

    def get_transaction_receipt(
            self, txn_hash: TxHash, timeout=None
    ) -> Optional[TxReceipt]:
        try:
            if not timeout:
                tx_receipt = self.w3.eth.get_transaction_receipt(txn_hash)
            else:
                try:
                    tx_receipt = self.w3.eth.wait_for_transaction_receipt(
                        txn_hash, timeout=timeout
                    )
                except TimeExhausted:
                    return None

            # Parity returns tx_receipt even is tx is still pending, so we check `blockNumber` is not None
            return (
                tx_receipt
                if tx_receipt and tx_receipt["blockNumber"] is not None
                else None
            )
        except TransactionNotFound:
            return None

    def get_transaction_receipts(
            self,
            txn_hashes: Sequence[TxHash],
    ) -> list[Optional[TxReceipt]]:
        if not txn_hashes:
            return []
        payload = [
            {
                "id": i,
                "jsonrpc": "2.0",
                "method": "eth_getTransactionReceipt",
                "params": [HexBytes(tx_hash).hex()],
            }
            for i, tx_hash in enumerate(txn_hashes)
        ]
        results = self.raw_batch_request(payload)
        receipts = []
        for tx_receipt in results:
            # Parity returns tx_receipt even is tx is still pending, so we check `blockNumber` is not None
            if tx_receipt and tx_receipt["blockNumber"] is not None:
                receipts.append(receipt_formatter(tx_receipt))
            else:
                receipts.append(None)
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

    def is_contract(self, contract_address: ChecksumAddress) -> bool:
        return bool(self.w3.eth.get_code(contract_address))

    @tx_with_exception_handling
    def send_transaction(self, transaction_dict: TxParams) -> HexBytes:
        return self.w3.eth.send_transaction(transaction_dict)

    @tx_with_exception_handling
    def send_raw_transaction(self, raw_transaction: bytes | HexStr) -> HexBytes:
        return self.w3.eth.send_raw_transaction(bytes(raw_transaction))

    def send_unsigned_transaction(
            self,
            tx: TxParams,
            private_key: Optional[str] = None,
            public_key: Optional[str] = None,
            retry: bool = False,
            block_identifier: Optional[BlockIdentifier] = "pending",
    ) -> HexBytes:
        """
        Send a tx using an unlocked public key in the node or a private key. Both `public_key` and
        `private_key` cannot be `None`

        :param tx:
        :param private_key:
        :param public_key:
        :param retry: Retry if a problem with nonce is found
        :param block_identifier: For nonce calculation, recommended is `pending`
        :return: tx hash
        """

        # TODO Refactor this method, it's not working well with new version of the nodes
        if private_key:
            address = Account.from_key(private_key).address
        elif public_key:
            address = public_key
        else:
            raise ValueError(
                "Ethereum account was not configured or unlocked in the node:"
                " no ethereum account provided. Need a public_key or private_key"
            )

        if tx.get("nonce") is None:
            tx["nonce"] = self.get_nonce(
                address, block_identifier=block_identifier
            )

        number_errors = 5
        while number_errors >= 0:
            try:
                if private_key:
                    signed_tx = self.w3.eth.account.sign_transaction(
                        tx, private_key=private_key
                    )
                    # TODO logger.debug
                    # f"Sending {tx['value']} wei from {address} to {tx['to']}"
                    try:
                        return self.send_raw_transaction(signed_tx.rawTransaction)
                    except TransactionAlreadyImported as e:
                        # Sometimes Parity 2.2.11 fails with Transaction already imported, even if it's not, but it's
                        # processed
                        tx_hash = signed_tx.hash
                        # TODO logger.error
                        # f"Transaction with tx-hash={tx_hash.hex()} already imported: {str(e)}"
                        return tx_hash
                elif public_key:
                    tx["from"] = address
                    return self.send_transaction(tx)
            except ReplacementTransactionUnderpriced as e:
                if not retry or not number_errors:
                    raise e
                current_nonce = tx["nonce"]
                tx["nonce"] = max(
                    current_nonce + 1,
                    self.get_nonce(
                        address, block_identifier=block_identifier
                    ),
                )
                # TODO logger.error
                # f"Tx with nonce={current_nonce} was already sent for address={address}, retrying with nonce={tx['nonce']}"

            except InvalidNonce as e:
                if not retry or not number_errors:
                    raise e
                # TODO logger.error
                # f"address={address} Tx with invalid nonce={tx['nonce']}, retrying recovering nonce again"
                tx["nonce"] = self.get_nonce(
                    address, block_identifier=block_identifier
                )
                number_errors -= 1

    def send_eth_to(
            self,
            private_key: str,
            to: str,
            gas_price: int,
            value: Wei,
            gas: Optional[int] = None,
            nonce: Optional[int] = None,
            retry: bool = False,
            block_identifier: Optional[BlockIdentifier] = "pending",
    ) -> bytes:
        """
        Send ether using configured account

        :param private_key: to
        :param to: to
        :param gas_price: gas_price
        :param value: value(wei)
        :param gas: gas, defaults to 22000
        :param retry: Retry if a problem is found
        :param nonce: Nonce of sender account
        :param block_identifier: Block identifier for nonce calculation
        :return: tx_hash
        """

        assert is_checksum_address(to)

        account = Account.from_key(private_key)

        tx: TxParams = {
            "from": account.address,
            "to": to,
            "value": value,
            "gas": gas or Wei(self.estimate_gas(to, account.address, value)),
            "gasPrice": Wei(gas_price),
            "chainId": self.get_chain_id(),
        }

        if nonce is not None:
            tx["nonce"] = Nonce(nonce)

        return self.send_unsigned_transaction(
            tx, private_key=private_key, retry=retry, block_identifier=block_identifier
        )

    def check_tx_with_confirmations(
            self, tx_hash: TxHash, confirmations: int
    ) -> bool:
        """
        Check tx hash and make sure it has the confirmations required

        :param tx_hash: Hash of the tx
        :param confirmations: Minimum number of confirmations required
        :return: True if tx was mined with the number of confirmations required, False otherwise
        """
        tx_receipt = self.get_transaction_receipt(tx_hash)
        if not tx_receipt or tx_receipt["blockNumber"] is None:
            # If `tx_receipt` exists but `blockNumber` is `None`, tx is still pending (just Parity)
            return False
        else:
            return (
                           self.w3.eth.block_number - tx_receipt["blockNumber"]
                   ) >= confirmations

    ################################################################################
    # Batch call
    ################################################################################

    def _batch_call_custom(
            self,
            payloads: Iterable[dict[str, Any]],
            raise_exception: bool = True,
            block_identifier: Optional[BlockIdentifier] = "latest",
            batch_size: Optional[int] = None,
    ) -> list[Optional[Any]]:
        """
        Do batch requests of multiple contract calls (`eth_call`)

        :param payloads: Iterable of Dictionaries with at least {'data': '<hex-string>',
            'output_type': <solidity-output-type>, 'to': '<checksummed-address>'}. `from` can also be provided and if
            `fn_name` is provided it will be used for debugging purposes
        :param raise_exception: If False, exception will not be raised if there's any problem and instead `None` will
            be returned as the value
        :param block_identifier: `latest` by default
        :param batch_size: If `payload` length is bigger than size, it will be split into smaller chunks before
            sending to the server
        :return: List with the ABI decoded return values
        :raises: ValueError if raise_exception=True
        """
        if not payloads:
            return []

        queries = []
        for i, payload in enumerate(payloads):
            assert "data" in payload, "`data` not present"
            assert "to" in payload, "`to` not present"
            assert "output_type" in payload, "`output-type` not present"

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
                raise ConnectionError(
                    f"Error connecting to {self.rpc}: {response.text}"
                )

            results = response.json()

            # If there's an error some nodes return a json instead of a list
            if isinstance(results, dict) and "error" in results:
                raise ValueError(f"Batch call custom problem with payload={chunk}, result={results})")

            all_results.extend(results)

        return_values: list[Optional[Any]] = []
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
                    decoded_values = eth_abi.decode(
                        output_type, HexBytes(result["result"])
                    )
                    normalized_data = map_abi_data(
                        BASE_RETURN_NORMALIZERS, output_type, decoded_values
                    )
                    if len(normalized_data) == 1:
                        return_values.append(normalized_data[0])
                    else:
                        return_values.append(normalized_data)
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

        return self._batch_call_custom(
            payloads, raise_exception=raise_exception, block_identifier=block_identifier
        )

    def raw_batch_request(
            self,
            payload: list[dict[str, Any]],
            batch_size: Optional[int] = None
    ) -> Iterable[Optional[dict[str, Any]]]:
        """
        Perform a raw batch JSON RPC call

        :param payload: Batch request payload. Make sure all provided `ids` inside the payload are different
        :param batch_size: If `payload` length is bigger than size, it will be split into smaller chunks before
            sending to the server
        :return:
        :raises: ValueError
        """

        batch_size = batch_size or self.batch_request_max_size

        all_results = []
        for chunk in chunks(payload, batch_size):
            response = self.http_session.post(
                self.rpc, json=chunk, timeout=self.slow_timeout
            )

            if not response.ok:
                raise ValueError(
                    f"Problem doing raw batch request with payload={chunk}"
                    f" status_code={response.status_code} result={response.content}")

            results = response.json()

            # If there's an error some nodes return a json instead of a list
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
            contract_functions: Sequence[ContractFunction],
            from_address: Optional[ChecksumAddress] = None,
            raise_exception: bool = True,
            force_batch_call: bool = False,
            block_identifier: Optional[BlockIdentifier] = "latest",
    ) -> list[Optional[Union[bytes, Any]]]:
        """
        Call multiple functions. ``Multicall`` contract by MakerDAO will be used by default if available

        :param contract_functions:
        :param from_address: Only available when ``Multicall`` is not used
        :param raise_exception: If ``True``, raise ``BatchCallException`` if one of the calls fails
        :param force_batch_call: If ``True``, ignore multicall and always use batch calls to get the
            result (less optimal). If ``False``, more optimal way will be tried.
        :param block_identifier:
        :return: List of elements decoded to their types, ``None`` if they cannot be decoded and
            bytes if a revert error is returned and ``raise_exception=False``
        :raises: BatchCallException
        """
        if self.multicall and not force_batch_call:  # Multicall is more optimal
            return [
                result.return_data_decoded
                for result in self.multicall.try_aggregate(
                    contract_functions,
                    require_success=raise_exception,
                    block_identifier=block_identifier,
                )
            ]
        else:
            return self._batch_call(
                contract_functions,
                from_address=from_address,
                raise_exception=raise_exception,
                block_identifier=block_identifier,
            )

    # === Tracing

    @staticmethod
    def filter_out_errored_traces(
            internal_txs: Sequence[dict[str, Any]]
    ) -> Sequence[dict[str, Any]]:
        """
        Filter out errored transactions (traces that are errored or that have an errored parent)

        :param internal_txs: Traces for the SAME ethereum tx, sorted ascending by `trace_address`
            `sorted(t, key = lambda i: i['traceAddress'])`. It's the default output from methods returning `traces` like
            `trace_block` or `trace_transaction`
        :return: List of not errored traces
        """
        new_list = []
        errored_trace_address: Optional[list[int]] = None
        for internal_tx in internal_txs:
            if internal_tx.get("error") is not None:
                errored_trace_address = internal_tx["traceAddress"]
            elif (
                    errored_trace_address is not None
                    and internal_tx["traceAddress"][: len(errored_trace_address)]
                    == errored_trace_address
            ):
                continue
            else:
                new_list.append(internal_tx)
        return new_list

    def get_previous_trace(
            self,
            tx_hash: TxHash,
            trace_address: Sequence[int],
            number_traces: int = 1,
            skip_delegate_calls: bool = False,
    ) -> Optional[dict[str, Any]]:
        """
        :param tx_hash:
        :param trace_address:
        :param number_traces: Number of traces to skip, by default get the immediately previous one
        :param skip_delegate_calls: If True filter out delegate calls
        :return: Parent trace for a trace
        :raises: ``ValueError`` if tracing is not supported
        """
        if len(trace_address) < number_traces:
            return None

        trace_address = trace_address[:-number_traces]
        traces = reversed(self.trace_transaction(tx_hash))
        for trace in traces:
            if trace_address == trace["traceAddress"]:
                if (
                        skip_delegate_calls
                        and trace["action"].get("callType") == "delegatecall"
                ):
                    trace_address = trace_address[:-1]
                else:
                    return trace

    def get_next_traces(
            self,
            tx_hash: TxHash,
            trace_address: Sequence[int],
            remove_delegate_calls: bool = False,
            remove_calls: bool = False,
    ) -> list[dict[str, Any]]:
        """
        :param tx_hash:
        :param trace_address:
        :param remove_delegate_calls: If True remove delegate calls from result
        :param remove_calls: If True remove calls from result
        :return: Children for a trace, E.g. if address is [0, 1] and number_traces = 1, it will return [0, 1, x]
        :raises: ``ValueError`` if tracing is not supported
        """
        trace_address_len = len(trace_address)
        traces = []
        for trace in self.trace_transaction(tx_hash):
            if (
                    trace_address_len + 1 == len(trace["traceAddress"])
                    and trace_address == trace["traceAddress"][:-1]
            ):
                if (
                        remove_delegate_calls
                        and trace["action"].get("callType") == "delegatecall"
                ):
                    pass
                elif remove_calls and trace["action"].get("callType") == "call":
                    pass
                else:
                    traces.append(trace)
        return traces

    def trace_block(self, block_identifier: BlockIdentifier) -> list[BlockTrace]:
        return self.slow_w3.tracing.trace_block(block_identifier)

    def trace_blocks(
            self, block_identifiers: list[BlockIdentifier]
    ) -> list[list[dict[str, Any]]]:
        if not block_identifiers:
            return []
        payload = [
            {
                "id": i,
                "jsonrpc": "2.0",
                "method": "trace_block",
                "params": [
                    hex(block_identifier)
                    if isinstance(block_identifier, int)
                    else block_identifier
                ],
            }
            for i, block_identifier in enumerate(block_identifiers)
        ]

        results = self.raw_batch_request(payload)
        return [trace_list_result_formatter(block_traces) for block_traces in results]

    def trace_transaction(self, tx_hash: TxHash) -> list[FilterTrace]:
        """
        :param tx_hash:
        :return: List of internal txs for `tx_hash`
        """
        return self.slow_w3.tracing.trace_transaction(tx_hash)

    def trace_transactions(
            self, tx_hashes: Sequence[TxHash]
    ) -> list[list[FilterTrace]]:
        """
        :param tx_hashes:
        :return: For every `tx_hash` a list of internal txs (in the same order as the `tx_hashes` were provided)
        """
        if not tx_hashes:
            return []
        payload = [
            {
                "id": i,
                "jsonrpc": "2.0",
                "method": "trace_transaction",
                "params": [HexBytes(tx_hash).hex()],
            }
            for i, tx_hash in enumerate(tx_hashes)
        ]
        results = self.raw_batch_request(payload)
        return [trace_list_result_formatter(tx_traces) for tx_traces in results]

    def trace_filter(
            self,
            from_block: int = 1,
            to_block: Optional[int] = None,
            from_address: Optional[Sequence[ChecksumAddress]] = None,
            to_address: Optional[Sequence[ChecksumAddress]] = None,
            after: Optional[int] = None,
            count: Optional[int] = None,
    ) -> list[FilterTrace]:
        """
        Get events using ``trace_filter`` method

        :param from_block: Quantity or Tag - (optional) From this block. `0` is not working, it needs to be `>= 1`
        :param to_block: Quantity or Tag - (optional) To this block.
        :param from_address: Array - (optional) Sent from these addresses.
        :param to_address: Address - (optional) Sent to these addresses.
        :param after: Quantity - (optional) The offset trace number
        :param count: Quantity - (optional) Integer number of traces to display in a batch.
        :return:

        .. code-block:: python

            [
                {
                    "action": {
                        "callType": "call",
                        "from": "0x32be343b94f860124dc4fee278fdcbd38c102d88",
                        "gas": "0x4c40d",
                        "input": "0x",
                        "to": "0x8bbb73bcb5d553b5a556358d27625323fd781d37",
                        "value": "0x3f0650ec47fd240000"
                    },
                    "blockHash": "0x86df301bcdd8248d982dbf039f09faf792684e1aeee99d5b58b77d620008b80f",
                    "blockNumber": 3068183,
                    "result": {
                        "gasUsed": "0x0",
                        "output": "0x"
                    },
                    "subtraces": 0,
                    "traceAddress": [],
                    "transactionHash": "0x3321a7708b1083130bd78da0d62ead9f6683033231617c9d268e2c7e3fa6c104",
                    "transactionPosition": 3,
                    "type": "call"
                },
                {
                    "action": {
                        "from": "0x3b169a0fb55ea0b6bafe54c272b1fe4983742bf7",
                        "gas": "0x49b0b",
                        "init": "0x608060405234801561001057600080fd5b5060405161060a38038061060a833981018060405281019080805190602001909291908051820192919060200180519060200190929190805190602001909291908051906020019092919050505084848160008173ffffffffffffffffffffffffffffffffffffffff1614151515610116576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260248152602001807f496e76616c6964206d617374657220636f707920616464726573732070726f7681526020017f696465640000000000000000000000000000000000000000000000000000000081525060400191505060405180910390fd5b806000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550506000815111156101a35773ffffffffffffffffffffffffffffffffffffffff60005416600080835160208501846127105a03f46040513d6000823e600082141561019f573d81fd5b5050505b5050600081111561036d57600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614156102b7578273ffffffffffffffffffffffffffffffffffffffff166108fc829081150290604051600060405180830381858888f1935050505015156102b2576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260268152602001807f436f756c64206e6f74207061792073616665206372656174696f6e207769746881526020017f206574686572000000000000000000000000000000000000000000000000000081525060400191505060405180910390fd5b61036c565b6102d1828483610377640100000000026401000000009004565b151561036b576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260268152602001807f436f756c64206e6f74207061792073616665206372656174696f6e207769746881526020017f20746f6b656e000000000000000000000000000000000000000000000000000081525060400191505060405180910390fd5b5b5b5050505050610490565b600060608383604051602401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001828152602001925050506040516020818303038152906040527fa9059cbb000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505090506000808251602084016000896127105a03f16040513d6000823e3d60008114610473576020811461047b5760009450610485565b829450610485565b8151158315171594505b505050509392505050565b61016b8061049f6000396000f30060806040526004361061004c576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680634555d5c91461008b5780635c60da1b146100b6575b73ffffffffffffffffffffffffffffffffffffffff600054163660008037600080366000845af43d6000803e6000811415610086573d6000fd5b3d6000f35b34801561009757600080fd5b506100a061010d565b6040518082815260200191505060405180910390f35b3480156100c257600080fd5b506100cb610116565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b60006002905090565b60008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050905600a165627a7a7230582007fffd557dfc8c4d2fdf56ba6381a6ce5b65b6260e1492d87f26c6d4f1d0410800290000000000000000000000008942595a2dc5181df0465af0d7be08c8f23c93af00000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000d9e09beaeb338d81a7c5688358df0071d498811500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001b15f91a8c35300000000000000000000000000000000000000000000000000000000000001640ec78d9e00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000004000000000000000000000000f763ea5fbb191d47dc4b083dcdc3cdfb586468f8000000000000000000000000ad25c9717d04c0a12086a1d352c1ccf4bf5fcbf80000000000000000000000000da7155692446c80a4e7ad72018e586f20fa3bfe000000000000000000000000bce0cc48ce44e0ac9ee38df4d586afbacef191fa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                        "value": "0x0"
                    },
                    "blockHash": "0x03f9f64dfeb7807b5df608e6957dd4d521fd71685aac5533451d27f0abe03660",
                    "blockNumber": 3793534,
                    "result": {
                        "address": "0x61a7cc907c47c133d5ff5b685407201951fcbd08",
                        "code": "0x60806040526004361061004c576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680634555d5c91461008b5780635c60da1b146100b6575b73ffffffffffffffffffffffffffffffffffffffff600054163660008037600080366000845af43d6000803e6000811415610086573d6000fd5b3d6000f35b34801561009757600080fd5b506100a061010d565b6040518082815260200191505060405180910390f35b3480156100c257600080fd5b506100cb610116565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b60006002905090565b60008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050905600a165627a7a7230582007fffd557dfc8c4d2fdf56ba6381a6ce5b65b6260e1492d87f26c6d4f1d041080029",
                        "gasUsed": "0x4683f"
                    },
                    "subtraces": 2,
                    "traceAddress": [],
                    "transactionHash": "0x6c7e8f8778d33d81b29c4bd7526ee50a4cea340d69eed6c89ada4e6fab731789",
                    "transactionPosition": 1,
                    "type": "create"
                },
                {
                    'action': {
                        'address': '0x4440adafbc6c4e45c299451c0eedc7c8b98c14ac',
                        'balance': '0x0',
                        'refundAddress': '0x0000000000000000000000000000000000000000'
                    },
                    'blockHash': '0x8512d367492371edf44ebcbbbd935bc434946dddc2b126cb558df5906012186c',
                    'blockNumber': 7829689,
                    'result': None,
                    'subtraces': 0,
                    'traceAddress': [0, 0, 0, 0, 0, 0],
                    'transactionHash': '0x5f7af6aa390f9f8dd79ee692c37cbde76bb7869768b1bac438b6d176c94f637d',
                    'transactionPosition': 35,
                    'type': 'suicide'
                }
            ]

        """
        assert (
                from_address or to_address
        ), "You must provide at least `from_address` or `to_address`"
        parameters: FilterParams = {}
        if after:
            parameters["after"] = after
        if count:
            parameters["count"] = count
        if from_block:
            parameters["fromBlock"] = HexStr("0x%x" % from_block)
        if to_block:
            parameters["toBlock"] = HexStr("0x%x" % to_block)
        if from_address:
            parameters["fromAddress"] = from_address
        if to_address:
            parameters["toAddress"] = to_address

        return self.slow_w3.tracing.trace_filter(parameters)
