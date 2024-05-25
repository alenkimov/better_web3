import asyncio
from typing import Iterable, AsyncGenerator

from better_proxy import Proxy
from eth_account.signers.local import LocalAccount
from eth_typing import ChecksumAddress, HexStr, Address, Hash32
from eth_utils import to_wei
from hexbytes import HexBytes
from web3 import AsyncWeb3, AsyncHTTPProvider
from web3.contract.async_contract import AsyncContractFunction
from web3.middleware import ExtraDataToPOAMiddleware
from web3.types import (
    BlockIdentifier,
    Nonce,
    TxParams,
    Wei,
)

from .utils import tx_url
from .models import Explorer, NativeCurrency


class Chain(AsyncWeb3):
    provider: AsyncHTTPProvider

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
            eip1559: bool = True,
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
        super().__init__(provider=http_provider)

        if use_poa_middleware:
            self.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

        self.default_batch_request_size = batch_request_size
        self.default_batch_request_delay = batch_request_delay
        self.default_gas_price = to_wei(gas_price, fee_unit) if gas_price else None
        self.default_max_fee_per_gas = to_wei(max_fee_per_gas, fee_unit) if gas_price else None
        self.default_max_priority_fee_per_gas = to_wei(max_priority_fee_per_gas, fee_unit) if gas_price else None

        self._proxy = None
        self.proxy = proxy

    def __str__(self):
        return f"{self.name}"

    def __repr__(self):
        return f"{self.__class__.__name__}(rpc={self.provider.endpoint_uri}, name={self.name})"

    @property
    def proxy(self) -> Proxy | None:
        return self._proxy

    @proxy.setter
    def proxy(self, proxy: str | Proxy | None):
        if proxy is None:
            self._proxy = None
            if "proxy" in self.provider._request_kwargs:
                del self.provider._request_kwargs["proxy"]
            return

        if isinstance(proxy, str):
            self._proxy = Proxy.from_str(proxy)

        self.provider._request_kwargs["proxy"] = self._proxy.as_url

    def tx_urls(
            self, tx_hash: HexBytes | HexStr | str,
    ) -> dict[str: str]:  # dict[explorer_name: url]
        if not self.explorers:
            raise ValueError("No explorers")

        if isinstance(tx_hash, HexBytes):
            tx_hash = tx_hash.hex()

        return {explorer.name: tx_url(explorer.url, tx_hash) for explorer in self.explorers}

    async def is_eip1559_supported(self) -> bool:
        """
        :return: True if EIP1559 is supported by the node, False otherwise
        """
        last_block = await self.eth.get_block("latest")
        return True if "baseFeePerGas" in last_block else False

    ################################################################################
    # Transaction
    ################################################################################

    async def check_tx_with_confirmations(
            self,
            tx_hash: Hash32 | HexBytes | HexStr,
            confirmations: int,
    ) -> bool:
        tx_receipt = await self.eth.get_transaction_receipt(tx_hash)

        if not tx_receipt or tx_receipt["blockNumber"] is None:
            # If `tx_receipt` exists but `blockNumber` is `None`,
            # the transaction is still pending (only for Parity).
            return False
        else:
            block_number = await self.eth.block_number
            confirmations_count = block_number - tx_receipt["blockNumber"]

            return confirmations_count >= confirmations

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

        tx_params["chainId"] = await self.eth.chain_id

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
            tx_params["nonce"] = await self.eth.get_transaction_count(address_from)

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
            tx_params["maxFeePerGas"] = max_fee_per_gas or await self.eth.gas_price
            tx_params["maxPriorityFeePerGas"] = max_priority_fee_per_gas or await self.eth.max_priority_fee
        else:
            tx_params["gasPrice"] = gas_price or await self.eth.gas_price

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
        tx_hash = await self.eth.send_raw_transaction(signed_tx.rawTransaction)
        return HexStr(tx_hash.hex())

    async def execute_fn(
            self,
            account: LocalAccount,
            fn: AsyncContractFunction,
            **kwargs,
    ) -> HexStr:
        tx = await self.build_tx(fn, address_from=account.address, **kwargs)
        return await self.sign_and_send_tx(account, tx)

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
        gas = await self.eth.estimate_gas(tx_params)
        tx_params = await self._build_tx_base_params(gas, tx_params=tx_params)
        tx_params = await self._build_tx_fee_params(
            gas_price, max_fee_per_gas, max_priority_fee_per_gas, tx_params=tx_params)
        return await self.sign_and_send_tx(account_from, tx_params)

    ################################################################################
    # Batch request
    ################################################################################

    async def _balances(
            self,
            addresses: Iterable[ChecksumAddress],
            block_identifier: BlockIdentifier = "latest",
    ):
        async with self.batch_requests() as batch:
            for address in addresses:
                batch.add(self.eth.get_balance(address, block_identifier))

            return await batch.async_execute()

    async def balances(
            self,
            addresses: Iterable[ChecksumAddress],
            block_identifier: BlockIdentifier = "latest",
            batch_size: int = None,
            delay: int = None,
    ) -> AsyncGenerator[tuple[ChecksumAddress, Wei], None]:
        batch_size = batch_size or self.default_batch_request_size
        delay = delay or self.default_batch_request_delay

        addresses = list(addresses)

        for i in range(0, len(addresses), batch_size):
            batch_addresses = addresses[i:i + batch_size]
            for address, balance in zip(batch_addresses, await self._balances(batch_addresses, block_identifier)):
                yield address, Wei(balance)

            if delay > 0 and i + batch_size < len(addresses):
                await asyncio.sleep(delay)
