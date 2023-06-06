from typing import TYPE_CHECKING, Iterable

import eth_abi
from eth_abi.exceptions import DecodingError
from eth_account import Account
from eth_typing import ChecksumAddress, BlockIdentifier
from hexbytes import HexBytes
from web3.exceptions import Web3Exception
from web3.types import Nonce, TxParams, Wei

from .abi import ERC20_ABI
from .contract import Contract
from .exceptions import InvalidERC20Info
from .model import Erc20Info
from ..utils import decode_string_or_bytes32, cache

if TYPE_CHECKING:
    from ..chain import Chain


class ERC20(Contract):
    def __init__(
            self,
            chain: "Chain",
            address: ChecksumAddress | str,
            abi=None,
    ):
        abi = abi or ERC20_ABI
        super().__init__(chain, address, abi)

    def get_balance(
            self,
            address: ChecksumAddress,
            block_identifier: BlockIdentifier | None = "latest",
    ) -> Wei:
        balance = self.functions.balanceOf(address).call(block_identifier=block_identifier)
        return balance

    def get_balances(
            self,
            addresses: Iterable[ChecksumAddress],
            block_identifier: BlockIdentifier | None = "latest",
    ) -> dict[ChecksumAddress: Wei]:
        if not addresses:
            return []
        addresses = list(addresses)
        balances = self.chain.batch_call(
            [self.functions.balanceOf(address) for address in addresses],
            block_identifier=block_identifier,
            raise_exception=False,
        )
        return {address: balance for address, balance in zip(addresses, balances)}

    @cache
    def get_name(self) -> str:
        data = self.functions.name().build_transaction(
            {"gas": Wei(0), "gasPrice": Wei(0)}
        )["data"]
        result = self.w3.eth.call({"to": self.address, "data": data})
        return decode_string_or_bytes32(result)

    @cache
    def get_symbol(self) -> str:
        data = self.functions.symbol().build_transaction(
            {"gas": Wei(0), "gasPrice": Wei(0)}
        )["data"]
        result = self.w3.eth.call({"to": self.address, "data": data})
        return decode_string_or_bytes32(result)

    @cache
    def get_decimals(self) -> int:
        return self.functions.decimals().call()

    # TODO Эта функция не использует Chain.batch_call и, таким образом, дублирует код
    @cache
    def get_info(self) -> Erc20Info:
        """
        Get erc20 information (`name`, `symbol` and `decimals`). Use batching to get
        all info in the same request.
        """
        params: TxParams = {
            "gas": Wei(0),
            "gasPrice": Wei(0),
        }  # Prevent executing tx, we are just interested on "data"
        datas = [
            self.functions.name().build_transaction(params)["data"],
            self.functions.symbol().build_transaction(params)["data"],
            self.functions.decimals().build_transaction(params)["data"],
        ]
        payload = [
            {
                "id": i,
                "jsonrpc": "2.0",
                "method": "eth_call",
                "params": [{"to": self.address, "data": data}, "latest"],
            }
            for i, data in enumerate(datas)
        ]
        response = self.chain.http_session.post(
            self.chain.rpc,
            json=payload,
            timeout=self.chain.slow_timeout,
        )
        if not response.ok:
            raise InvalidERC20Info(response.content)
        try:
            response_json = sorted(response.json(), key=lambda x: x["id"])
            errors = [r["error"] for r in response_json if "error" in r]
            if errors:
                raise InvalidERC20Info(f"{self.address} - {errors}")
            results = [HexBytes(r["result"]) for r in response_json]
            name = decode_string_or_bytes32(results[0])
            symbol = decode_string_or_bytes32(results[1])
            decimals = eth_abi.decode(["uint8"], results[2])[0]
            return Erc20Info(name, symbol, decimals)
        except (Web3Exception, DecodingError, ValueError) as e:
            raise InvalidERC20Info from e

    def send_tokens(
            self,
            to: str,
            amount: int,
            private_key: str,
            nonce: int = None,
            gas_price: int = None,
            gas: int = None,
    ) -> bytes:
        account = Account.from_key(private_key)
        tx_options: TxParams = {"from": account.address}
        if nonce:
            tx_options["nonce"] = Nonce(nonce)
        if gas_price:
            tx_options["gasPrice"] = Wei(gas_price)
        if gas:
            tx_options["gas"] = Wei(gas)

        tx = self.functions.transfer(to, amount).build_transaction(tx_options)
        return self.chain.send_unsigned_transaction(
            tx, private_key=private_key
        )
