from dataclasses import dataclass
from functools import cached_property
from time import sleep

import requests
from eth_account.signers.local import LocalAccount
from eth_typing import BlockNumber, ChecksumAddress, HexStr, Address, Hash32
from hexbytes import HexBytes
from requests.adapters import HTTPAdapter
from web3 import HTTPProvider, Web3
from web3.contract.contract import ContractFunction
from web3.middleware import geth_poa_middleware
from web3.types import (
    BlockData,
    BlockIdentifier,
    Nonce,
    TxData,
    TxParams,
    TxReceipt,
    Wei,
)

from .batch_call import BatchCallManager
from .contract import Contract, Multicall, Disperse, ERC20, ERC721
from .utils import link_by_tx_hash


@dataclass
class NativeToken:
    symbol: str = "ETH"
    decimals: int = 18


class Chain:
    def __init__(
            self,
            rpc: str,
            *,
            name: str = "EVM Chain",
            is_testnet: bool = False,
            use_eip1559: bool = True,
            # Native token
            symbol: str = "ETH",
            decimals: int = 18,
            # Explorer
            explorer_url: str = None,
            # Connection settings
            provider_timeout: int = 15,
            slow_provider_timeout: int = 60,
            retry_count: int = 3,
            # Middlewares
            use_poa_middleware: bool = True,
            # Multicall
            multicall_v3_contract_address: ChecksumAddress | str = None,
            # Disperse
            disperse_contract_address: ChecksumAddress | str = None,
            # Batch request
            batch_request_size: int = 10,
            batch_request_delay: int = 1,
            # Tx params
            # legacy pricing
            gas_price: Wei | int = None,
            # dynamic fee pricing
            max_fee_per_gas: Wei | int = None,
            max_priority_fee_per_gas: Wei | int = None,
    ):
        self._rpc = rpc
        self.name = name
        self.is_testnet = is_testnet
        self.token = NativeToken(symbol=symbol, decimals=decimals)
        self.explorer_url = explorer_url
        self.use_eip1559 = use_eip1559

        self.http_session = self._prepare_http_session(retry_count)
        self.timeout = provider_timeout

        self.w3_provider = self._create_http_provider(provider_timeout)

        self.w3 = Web3(provider=self.w3_provider)

        if use_poa_middleware:
            self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)

        self.multicall = Multicall(chain=self, address=multicall_v3_contract_address)
        self.disperse = Disperse(chain=self, address=disperse_contract_address)

        self.batch_request = BatchCallManager(
            self, batch_request_size, batch_request_delay)

        self.default_gas_price = gas_price
        self.default_max_fee_per_gas = max_fee_per_gas
        self.default_max_priority_fee_per_gas = max_priority_fee_per_gas

    def _create_http_provider(self, timeout: int) -> HTTPProvider:
        return HTTPProvider(
            self._rpc,
            request_kwargs={"timeout": timeout},
            session=self.http_session,
        )

    def __repr__(self):
        return f"Chain(rpc=\"{self.rpc})\""

    def __str__(self):
        return f"<{self.name}>"

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
            max_retries=retry_count,  # Nodes are not very responsive sometimes
            pool_block=False,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    @property
    def rpc(self):
        return self._rpc

    def get_link_by_tx_hash(self, tx_hash: HexBytes | HexStr | str):
        if self.explorer_url is None:
            raise ValueError("Set explorer_url before using this method")

        if isinstance(tx_hash, HexBytes):
            tx_hash = tx_hash.hex()
        return link_by_tx_hash(self.explorer_url, tx_hash)

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
    # Shortcuts
    ################################################################################

    @cached_property
    def chain_id(self) -> int:
        return self.w3.eth.chain_id

    @cached_property
    def client_version(self) -> str:
        return self.w3.client_version

    @cached_property
    def is_eip1559_supported(self) -> bool:
        """
        :return: True if EIP1559 is supported by the node, False otherwise
        """
        last_block = self.get_block("latest")
        return True if "baseFeePerGas" in last_block else False

    def is_contract(self, contract_address: Address | ChecksumAddress | str) -> bool:
        return bool(self.w3.eth.get_code(contract_address))

    def get_current_block_number(self) -> BlockNumber:
        return self.w3.eth.block_number

    def get_nonce(self, address: Address | ChecksumAddress | str) -> int:
        return self.w3.eth.get_transaction_count(address)

    def get_balance(
            self,
            address: Address | ChecksumAddress | str,
            block_identifier: BlockIdentifier = "latest",
    ) -> Wei:
        return self.w3.eth.get_balance(address, block_identifier)

    def get_tx(self, tx_hash: Hash32 | HexBytes | HexStr) -> TxData:
        return self.w3.eth.get_transaction(tx_hash)

    def get_tx_receipt(self, tx_hash: Hash32 | HexBytes | HexStr) -> TxReceipt:
        return self.w3.eth.get_transaction_receipt(tx_hash)

    def wait_for_tx_receipt(
            self,
            tx_hash: Hash32 | HexBytes | HexStr,
            timeout: float = 120,
            poll_latency: float = 0.1
    ) -> TxReceipt:
        """
        raises: TimeExhausted:
                 Raised when a method has not retrieved the desired result within a specified timeout.
                 TransactionNotFound:
                 Raised when a tx hash used to look up a tx in a jsonrpc call cannot be found.
        """
        tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout, poll_latency)

        # Add extra sleep to let tx propogate correctly
        sleep(1)
        return tx_receipt

    def get_block(
            self,
            block_identifier: BlockIdentifier,
            full_transactions: bool = False
    ) -> BlockData:
        return self.w3.eth.get_block(block_identifier, full_transactions=full_transactions)

    def check_tx_with_confirmations(
            self,
            tx_hash: Hash32 | HexBytes | HexStr,
            confirmations: int
    ) -> bool:
        tx_receipt = self.get_tx_receipt(tx_hash)

        if not tx_receipt or tx_receipt["blockNumber"] is None:
            # If `tx_receipt` exists but `blockNumber` is `None`,
            # the transaction is still pending (only for Parity).
            return False
        else:
            block_number = self.w3.eth.block_number
            confirmations_count = block_number - tx_receipt["blockNumber"]

            return confirmations_count >= confirmations

    def transfer(
            self,
            account_from: LocalAccount,
            address_to: Address | ChecksumAddress | str,
            value: Wei | int,
            *,
            gas: int = None,
            nonce: Nonce | int = None,
            # legacy pricing
            gas_price: Wei | int = None,
            # dynamic fee pricing
            max_fee_per_gas: Wei | int = None,
            max_priority_fee_per_gas: Wei | int = None,
    ) -> HexStr:
        gas_price = gas_price or self.default_gas_price
        tx_params = self._build_tx_base_params(gas, account_from.address, address_to, nonce, value)
        gas = self.w3.eth.estimate_gas(tx_params)
        tx_params = self._build_tx_base_params(gas, tx_params=tx_params)
        tx_params = self._build_tx_fee_params(
            gas_price, max_fee_per_gas, max_priority_fee_per_gas, tx_params=tx_params)
        return self.sign_and_send_tx(account_from, tx_params)

    def transfer_all(
            self,
            account_from: LocalAccount,
            address_to: Address | ChecksumAddress | str,
            *,
            gas: int = None,
            nonce: Nonce | int = None,
            # legacy pricing
            gas_price: Wei | int = None,
            # dynamic fee pricing
            max_fee_per_gas: Wei | int = None,
            max_priority_fee_per_gas: Wei | int = None,
    ):
        raise NotImplementedError  # TODO Реализовать метод Chain.transfer_all()

    ################################################################################
    # Gas price shortcuts
    ################################################################################

    def request_gas_price(self) -> Wei:
        return self.w3.eth.gas_price

    def request_max_priority_fee(self) -> Wei:
        return self.w3.eth.max_priority_fee

    ################################################################################
    # Working with transactions
    ################################################################################

    def _send_tx(self, tx: TxParams) -> HexBytes:
        return self.w3.eth.send_transaction(tx)

    def _send_raw_tx(self, raw_tx: bytes | HexStr) -> HexBytes:
        return self.w3.eth.send_raw_transaction(bytes(raw_tx))

    def _build_tx_base_params(
            self,
            gas: int = None,
            address_from: Address | ChecksumAddress | str = None,
            address_to: Address | ChecksumAddress | str = None,
            nonce: Nonce | int = None,
            value: Wei | int = None,
            *,
            tx_params: TxParams = None,
    ) -> TxParams:
        if tx_params is None:
            tx_params = dict()
        tx_params = tx_params.copy()

        tx_params["chainId"] = self.chain_id

        if gas is not None:
            tx_params["gas"] = gas
        if address_from is not None:
            tx_params["from"] = address_from
        if address_to is not None:
            tx_params["to"] = address_to
        if value is not None:
            tx_params["value"] = value

        if nonce is not None:
            tx_params["nonce"] = nonce
        elif address_from is not None:
            tx_params["nonce"] = self.get_nonce(address_from)

        return tx_params

    def _build_tx_fee_params(
            self,
            # legacy pricing
            gas_price: Wei | int = None,
            # dynamic fee pricing
            max_fee_per_gas: Wei | int = None,
            max_priority_fee_per_gas: Wei | int = None,
            *,
            tx_params: TxParams = None,
    ) -> TxParams:
        if tx_params is None:
            tx_params = dict()
        tx_params = tx_params.copy()

        max_fee_per_gas = max_fee_per_gas or self.default_max_fee_per_gas
        max_priority_fee_per_gas = max_priority_fee_per_gas or self.default_max_priority_fee_per_gas

        if (self.is_eip1559_supported and
                ((gas_price is None and self.use_eip1559)
                 or max_fee_per_gas is not None
                 or max_priority_fee_per_gas is not None)):
            tx_params["maxFeePerGas"] = max_fee_per_gas or self.request_gas_price()
            tx_params["maxPriorityFeePerGas"] = max_priority_fee_per_gas or self.request_max_priority_fee()
        else:
            tx_params["gasPrice"] = gas_price or self.request_gas_price()

        return tx_params

    def build_tx(
            self,
            contract_function: ContractFunction,
            gas: int = None,
            address_from: Address | ChecksumAddress | str = None,
            address_to: Address | ChecksumAddress | str = None,
            nonce: Nonce | int = None,
            value: Wei | int = None,
            # legacy pricing
            gas_price: Wei | int = None,
            # dynamic fee pricing
            max_fee_per_gas: Wei | int = None,
            max_priority_fee_per_gas: Wei | int = None,
    ) -> TxParams:
        gas_price = gas_price or self.default_gas_price
        tx_params = self._build_tx_base_params(gas, address_from, address_to, nonce, value)
        gas = contract_function.estimate_gas(tx_params)
        tx_params = self._build_tx_base_params(gas, tx_params=tx_params)
        tx_params = self._build_tx_fee_params(
            gas_price, max_fee_per_gas, max_priority_fee_per_gas, tx_params=tx_params)
        return contract_function.build_transaction(tx_params)

    def sign_and_send_tx(self, account: LocalAccount, tx: TxParams) -> HexStr:
        signed_tx = account.sign_transaction(tx)
        tx_hash = self._send_raw_tx(signed_tx.rawTransaction)
        return HexStr(tx_hash.hex())

    def execute_fn(
            self,
            account: LocalAccount,
            fn: ContractFunction,
            *,
            gas: int = None,
            nonce: Nonce | int = None,
            value: Wei | int = None,
            # legacy pricing
            gas_price: Wei | int = None,
            # dynamic fee pricing
            max_fee_per_gas: Wei | int = None,
            max_priority_fee_per_gas: Wei | int = None,
    ) -> HexStr:
        tx = self.build_tx(
            fn,
            address_from=account.address,
            gas=gas,
            nonce=nonce,
            value=value,
            gas_price=gas_price,
            max_fee_per_gas=max_fee_per_gas,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
        )
        tx_hash = self.sign_and_send_tx(account, tx)
        return tx_hash
