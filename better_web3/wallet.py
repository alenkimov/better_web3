from functools import cached_property
from pathlib import Path

from eth_account.account import Account, LocalAccount
from eth_typing import ChecksumAddress, HexStr
from eth_utils import from_wei
from web3.types import TxReceipt, Wei

from . import Chain
from .utils import sign_message, load_lines


class Wallet:
    def __init__(self, account: LocalAccount):
        self.account = account

    def __repr__(self):
        return f"Wallet(address={self.address})"

    def __str__(self) -> str:
        return f"[{self.address}]"

    def __eq__(self, other):
        if isinstance(other, Wallet):
            return self.address == other.address
        return False

    @classmethod
    def generate(cls, extra_entropy: str = "") -> "Wallet":
        account = Account.create(extra_entropy)
        return cls(account)

    @classmethod
    def from_key(cls, private_key: str) -> "Wallet":
        account = Account.from_key(private_key)
        return cls(account)

    @classmethod
    def from_mnemonic(cls, mnemonic: str, passphrase: str = "") -> "Wallet":
        account = Account.from_key(mnemonic, passphrase)
        return cls(account)

    @classmethod
    def from_file(cls, filepath: Path | str) -> list["Wallet"]:
        return [cls.from_key(private_key) for private_key in load_lines(filepath)]

    @cached_property
    def private_key(self) -> str:
        return self.account.key.hex()

    @cached_property
    def address(self) -> ChecksumAddress:
        return self.account.address

    @cached_property
    def short_address(self) -> str:
        start = self.account.address[:6]
        end = self.account.address[-1:-4:-1]
        return f"{start}...{end}"

    def sign_message(self, message: str) -> str:
        return sign_message(message, self.account)

    def tx_hash(self, chain: Chain, tx_hash: HexStr | str, value: Wei | int = None) -> str:
        tx_hash_link = chain.get_link_by_tx_hash(tx_hash)
        message = f"{self} {chain} {tx_hash_link}"
        if value is not None:
            message += f"\n\tSent: {from_wei(value, 'ether')} {chain.token.symbol}"
        return message

    def tx_receipt(self, chain: Chain, tx_receipt: TxReceipt | str, value: Wei | int = None) -> str:
        tx_hash = tx_receipt.transactionHash.hex()
        message = self.tx_hash(chain, tx_hash, value)
        tx_fee_wei = tx_receipt.gasUsed * tx_receipt.effectiveGasPrice
        tx_fee = from_wei(tx_fee_wei, "ether")
        message += f"\n\tFee: {tx_fee} {chain.token.symbol}"
        return message
