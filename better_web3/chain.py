import asyncio
from dataclasses import dataclass

from eth_account.signers.local import LocalAccount
from eth_typing import BlockNumber, ChecksumAddress, HexStr, Address, Hash32
from eth_utils import to_wei
from hexbytes import HexBytes
from web3 import AsyncWeb3
from web3.contract.async_contract import AsyncContractFunction
from web3.middleware import async_geth_poa_middleware, async_simple_cache_middleware
from web3.types import (
    BlockData,
    BlockIdentifier,
    Nonce,
    TxData,
    TxParams,
    TxReceipt,
    Wei,
)

from .provider import CustomAsyncHTTPProvider
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
            # Proxy
            proxy: str = None,
            # Native token
            symbol: str = "ETH",
            decimals: int = 18,
            # Explorer
            explorer_url: str = None,
            # Connection settings
            provider_timeout: int = 15,
            # Middlewares
            use_poa_middleware: bool = True,
            use_cache_middleware: bool = True,
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

        self.w3_provider = CustomAsyncHTTPProvider(self._rpc, proxy=proxy, request_kwargs={"timeout": provider_timeout})
        self.w3 = AsyncWeb3(provider=self.w3_provider)

        if use_poa_middleware:
            self.w3.middleware_onion.inject(async_geth_poa_middleware, layer=0)

        if use_cache_middleware:
            self.w3.middleware_onion.add(async_simple_cache_middleware)

        self.multicall = Multicall(chain=self, address=multicall_v3_contract_address)
        self.disperse = Disperse(chain=self, address=disperse_contract_address)

        self.batch_request = BatchCallManager(
            self, batch_request_size, batch_request_delay)

        self.default_gas_price = gas_price
        self.default_max_fee_per_gas = max_fee_per_gas
        self.default_max_priority_fee_per_gas = max_priority_fee_per_gas

    def __str__(self):
        return f"{self.name}"

    def __repr__(self):
        return f"{self.__class__.__name__}(rpc={self.rpc}, name={self.name})"

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
            poll_latency: float = 0.1
    ) -> TxReceipt:
        """
        raises: TimeExhausted:
                 Raised when a method has not retrieved the desired result within a specified timeout.
                 TransactionNotFound:
                 Raised when a tx hash used to look up a tx in a jsonrpc call cannot be found.
        """
        tx_receipt = await self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout, poll_latency)

        # Add extra sleep to let tx propogate correctly
        await asyncio.sleep(1)
        return tx_receipt

    async def get_block(
            self,
            block_identifier: BlockIdentifier,
            full_transactions: bool = False
    ) -> BlockData:
        return await self.w3.eth.get_block(block_identifier, full_transactions=full_transactions)

    async def check_tx_with_confirmations(
            self,
            tx_hash: Hash32 | HexBytes | HexStr,
            confirmations: int
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
            # legacy pricing
            gas_price: Wei | int = None,
            # dynamic fee pricing
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
        tx = await self.build_tx(
            fn,
            address_from=account.address,
            gas=gas,
            nonce=nonce,
            value=value,
            gas_price=gas_price,
            max_fee_per_gas=max_fee_per_gas,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
        )
        tx_hash = await self.sign_and_send_tx(account, tx)
        return tx_hash


def load_chains(chains_data: dict, ensure_chain_id=False, **chain_kwargs) -> dict[int: Chain]:
    chains: dict[int: Chain] = {}
    minimal_balances: dict[int: Wei] = {}
    for net_mode, id_to_chain_data in chains_data.items():
        is_testnet = True if net_mode == "testnet" else False
        for chain_id, chain_data in id_to_chain_data.items():
            chain_id = int(chain_id)
            if "minimal_balance" in chain_data:
                minimal_balances[chain_id] = to_wei(chain_data.pop("minimal_balance"), "ether")
            if "gas_price" in chain_data:
                chain_data["gas_price"] = to_wei(chain_data["gas_price"], "gwei")
            if "max_fee_per_gas" in chain_data:
                chain_data["max_fee_per_gas"] = to_wei(chain_data["max_fee_per_gas"], "gwei")
            if "max_priority_fee_per_gas" in chain_data:
                chain_data["max_priority_fee_per_gas"] = to_wei(chain_data["max_priority_fee_per_gas"], "gwei")
            chain = Chain(**chain_data, is_testnet=is_testnet, **chain_kwargs)
            if ensure_chain_id and chain.chain_id == chain_id or not ensure_chain_id:
                chains[chain_id] = chain
    return chains, minimal_balances
