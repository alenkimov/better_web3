import asyncio

from better_proxy import Proxy
from eth_account.signers.local import LocalAccount
from eth_typing import BlockNumber, ChecksumAddress, HexStr, Address, Hash32
from eth_utils import to_wei
from hexbytes import HexBytes
from web3 import AsyncWeb3, AsyncHTTPProvider
from web3.contract.async_contract import AsyncContractFunction
from web3.middleware import ExtraDataToPOAMiddleware
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
from .contract import Contract
from .contracts import Multicall, Disperse, ERC20, ERC721
from .utils import tx_url, tx_hash_info, tx_receipt_info
from .models import Explorer, NativeCurrency


class Chain:
    def __init__(
            self,
            rpc: str,
            *,
            explorers: list[Explorer] = None,
            name: str = None,
            short_name: str = None,
            title: str = None,
            info_url: str = None,
            native_currency: NativeCurrency = None,
            # Connection settings
            provider_timeout: int = 15,
            proxy: str | Proxy = None,
            # Contracts
            multicall_v3_contract_address: ChecksumAddress | str = None,
            disperse_contract_address: ChecksumAddress | str = None,
            # Batch request
            batch_request_size: int = 10,
            batch_request_delay: int = 1,
            # Tx params
            fee_unit: str = "gwei",
            # legacy pricing
            gas_price: Wei | int = None,
            # dynamic fee pricing
            max_fee_per_gas: Wei | int = None,
            max_priority_fee_per_gas: Wei | int = None,
            # Features
            eip1559: bool = False,
            # Middleware
            use_poa_middleware: bool = True,
    ):
        self.explorers = explorers

        self.name = name
        self.short_name = short_name
        self.title = title
        self.info_url = info_url
        self.native_currency = native_currency or NativeCurrency()

        self.eip1559 = eip1559

        http_provider = AsyncHTTPProvider(
            rpc,
            request_kwargs={"timeout": provider_timeout},
        )
        http_provider.cache_allowed_requests = True
        self.w3 = AsyncWeb3(provider=http_provider)

        if use_poa_middleware:
            self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

        self.multicall = Multicall(chain=self, address=multicall_v3_contract_address)
        self.disperse = Disperse(chain=self, address=disperse_contract_address)

        self.batch_request = BatchCallManager(
            self, batch_request_size, batch_request_delay)

        self.default_gas_price = to_wei(gas_price, fee_unit) if gas_price else None
        self.default_max_fee_per_gas = to_wei(max_fee_per_gas, fee_unit) if gas_price else None
        self.default_max_priority_fee_per_gas = to_wei(max_priority_fee_per_gas, fee_unit) if gas_price else None

        self._proxy = None
        self.proxy = proxy

    def __str__(self):
        return f"{self.name}"

    def __repr__(self):
        return f"{self.__class__.__name__}(rpc={self.rpc}, name={self.name})"

    @property
    def provider(self) -> AsyncHTTPProvider:
        return self.w3.provider

    @provider.setter
    def provider(self, provider: AsyncHTTPProvider):
        self.w3.provider = provider

    @property
    def rpc(self):
        return self.provider.endpoint_uri

    @property
    def proxy(self) -> Proxy | None:
        return self._proxy

    @proxy.setter
    def proxy(self, proxy: str | Proxy | None):
        if proxy is None:
            self._proxy = None
            if "proxies" in self.provider._request_kwargs:
                del self.provider._request_kwargs["proxies"]
            return

        if isinstance(proxy, str):
            self._proxy = Proxy.from_str(proxy)

        self.provider._request_kwargs["proxies"] = {"http": self._proxy.as_url, "https": self._proxy.as_url}

    ################################################################################
    # Tx info shortcuts
    ################################################################################

    def tx_url(
            self,
            tx_hash: HexBytes | HexStr | str,
            explorer_name: str = None,
    ):
        if not self.explorers:
            raise ValueError("No explorers")

        target_explorer = None

        if explorer_name:
            for explorer in self.explorers:
                if explorer.name == explorer_name:
                    target_explorer = explorer
                    break

            if not target_explorer:
                raise ValueError("No explorer with this name")

        else:
            target_explorer = self.explorers[0]

        if isinstance(tx_hash, HexBytes):
            tx_hash = tx_hash.hex()

        return tx_url(target_explorer.url, tx_hash)

    def tx_hash_info(self, address: str, tx_hash: HexStr | str, value: Wei | int = None) -> str:
        return tx_hash_info(self, address, tx_hash, value)

    def tx_receipt_info(self, address: str, tx_receipt: TxReceipt, value: Wei | int = None) -> str:
        return tx_receipt_info(self, address, tx_receipt, value)

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

    async def chain_id(self) -> int:
        return await self.w3.eth.chain_id

    async def client_version(self) -> str:
        return await self.w3.client_version

    async def is_eip1559_supported(self) -> bool:
        """
        :return: True if EIP1559 is supported by the node, False otherwise
        """
        last_block = await self.get_block("latest")
        return True if "baseFeePerGas" in last_block else False

    async def is_contract(self, contract_address: Address | ChecksumAddress | str) -> bool:
        return bool(await self.w3.eth.get_code(contract_address))

    async def get_current_block_number(self) -> BlockNumber:
        return await self.w3.eth.block_number

    async def get_nonce(self, address: Address | ChecksumAddress | str) -> int:
        return await self.w3.eth.get_transaction_count(address)

    async def get_balance(
            self,
            address: Address | ChecksumAddress | str,
            block_identifier: BlockIdentifier = "latest",
    ) -> Wei:
        return await self.w3.eth.get_balance(address, block_identifier)

    async def get_tx(self, tx_hash: Hash32 | HexBytes | HexStr) -> TxData:
        return await self.w3.eth.get_transaction(tx_hash)

    async def get_tx_receipt(self, tx_hash: Hash32 | HexBytes | HexStr) -> TxReceipt:
        return await self.w3.eth.get_transaction_receipt(tx_hash)

    async def wait_for_tx_receipt(
            self,
            tx_hash: Hash32 | HexBytes | HexStr,
            timeout: float = 120,
            poll_latency: float = 0.1,
    ) -> TxReceipt:
        """
        raises: TimeExhausted:
                 Raised when a method has not retrieved the desired result within a specified timeout.
                 TransactionNotFound:
                 Raised when a tx hash used to look up a tx in a jsonrpc call cannot be found.
        """
        tx_receipt = await self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout, poll_latency)

        # Add extra sleep to let tx propagate correctly
        await asyncio.sleep(1)
        return tx_receipt

    async def get_block(
            self,
            block_identifier: BlockIdentifier,
            full_transactions: bool = False,
    ) -> BlockData:
        return await self.w3.eth.get_block(block_identifier, full_transactions=full_transactions)

    async def check_tx_with_confirmations(
            self,
            tx_hash: Hash32 | HexBytes | HexStr,
            confirmations: int,
    ) -> bool:
        tx_receipt = await self.get_tx_receipt(tx_hash)

        if not tx_receipt or tx_receipt["blockNumber"] is None:
            # If `tx_receipt` exists but `blockNumber` is `None`,
            # the transaction is still pending (only for Parity).
            return False
        else:
            block_number = await self.w3.eth.block_number
            confirmations_count = block_number - tx_receipt["blockNumber"]

            return confirmations_count >= confirmations

    async def transfer(
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
        tx_params = await self._build_tx_base_params(gas, account_from.address, address_to, nonce, value)
        gas = await self.w3.eth.estimate_gas(tx_params)
        tx_params = await self._build_tx_base_params(gas, tx_params=tx_params)
        tx_params = await self._build_tx_fee_params(
            gas_price, max_fee_per_gas, max_priority_fee_per_gas, tx_params=tx_params)
        return await self.sign_and_send_tx(account_from, tx_params)

    ################################################################################
    # Gas price shortcuts
    ################################################################################

    async def request_gas_price(self) -> Wei:
        return await self.w3.eth.gas_price

    async def request_max_priority_fee(self) -> Wei:
        return await self.w3.eth.max_priority_fee

    ################################################################################
    # Working with transactions
    ################################################################################

    async def _send_tx(self, tx: TxParams) -> HexBytes:
        return await self.w3.eth.send_transaction(tx)

    async def _send_raw_tx(self, raw_tx: bytes | HexStr) -> HexBytes:
        return await self.w3.eth.send_raw_transaction(bytes(raw_tx))

    async def _build_tx_base_params(
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

        tx_params["chainId"] = await self.chain_id()

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
            tx_params["nonce"] = await self.get_nonce(address_from)

        return tx_params

    async def _build_tx_fee_params(
            self,
            gas_price: Wei | int = None,
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
                ((gas_price is None and self.eip1559)
                 or max_fee_per_gas is not None
                 or max_priority_fee_per_gas is not None)):
            tx_params["maxFeePerGas"] = max_fee_per_gas or await self.request_gas_price()
            tx_params["maxPriorityFeePerGas"] = max_priority_fee_per_gas or await self.request_max_priority_fee()
        else:
            tx_params["gasPrice"] = gas_price or await self.request_gas_price()

        return tx_params

    async def build_tx(
            self,
            contract_function: AsyncContractFunction,
            gas: int = None,
            address_from: Address | ChecksumAddress | str = None,
            address_to: Address | ChecksumAddress | str = None,
            nonce: Nonce | int = None,
            value: Wei | int = None,
            gas_price: Wei | int = None,
            max_fee_per_gas: Wei | int = None,
            max_priority_fee_per_gas: Wei | int = None,
    ) -> TxParams:
        gas_price = gas_price or self.default_gas_price
        tx_params = await self._build_tx_base_params(gas, address_from, address_to, nonce, value)
        gas = await contract_function.estimate_gas(tx_params)
        tx_params = await self._build_tx_base_params(gas, tx_params=tx_params)
        tx_params = await self._build_tx_fee_params(
            gas_price, max_fee_per_gas, max_priority_fee_per_gas, tx_params=tx_params)
        return await contract_function.build_transaction(tx_params)

    async def sign_and_send_tx(self, account: LocalAccount, tx: TxParams) -> HexStr:
        signed_tx = account.sign_transaction(tx)
        tx_hash = await self._send_raw_tx(signed_tx.rawTransaction)
        return HexStr(tx_hash.hex())

    async def execute_fn(
            self,
            account: LocalAccount,
            fn: AsyncContractFunction,
            **kwargs,
    ) -> HexStr | TxReceipt:
        tx = await self.build_tx(fn, address_from=account.address, **kwargs)
        return await self.sign_and_send_tx(account, tx)
