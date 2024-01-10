from functools import cached_property
from pathlib import Path

from eth_account.account import Account, LocalAccount
from eth_typing import ChecksumAddress, HexStr
from eth_utils import from_wei
from web3.types import TxReceipt, Wei

from . import Chain
from .utils import sign_message, load_lines

Account.enable_unaudited_hdwallet_features()


class Wallet:
    def __init__(self, eth_account: LocalAccount):
        self.eth_account = eth_account

    def __str__(self) -> str:
        return self.address

    def __repr__(self):
        return f"{self.__class__.__name__}(private_key={self.short_private_key}, address={self.address})"

    def __hash__(self):
        return hash(self.eth_account)

    def __eq__(self, other):
        return self.eth_account == other.eth_account

    @classmethod
    def generate(cls, extra_entropy: str = "") -> "Wallet":
        eth_account = Account.create(extra_entropy)
        return cls(eth_account)

    @classmethod
    def from_key(cls, private_key: str) -> "Wallet":
        eth_account = Account.from_key(private_key)
        return cls(eth_account)

    @classmethod
    def from_mnemonic(cls, mnemonic: str, passphrase: str = "") -> "Wallet":
        eth_account = Account.from_mnemonic(mnemonic, passphrase)
        return cls(eth_account)

    @classmethod
    def from_file(cls, filepath: Path | str) -> list["Wallet"]:
        wallets = []
        for line in load_lines(filepath):
            wallet = None
            try:
                wallet = cls.from_key(line)
            except Exception:
                try:
                    wallet = cls.from_mnemonic(line)
                except Exception:
                    pass

            if wallet:
                wallets.append(wallet)
        return wallets

    @cached_property
    def private_key(self) -> str:
        return self.eth_account.key.hex()

    @cached_property
    def address(self) -> ChecksumAddress:
        return self.eth_account.address

    @property
    def short_private_key(self) -> str:
        start = self.private_key[:4]
        end = self.private_key[-4:]
        return f"{start}**{end}"

    @cached_property
    def short_address(self) -> str:
        start = self.address[:4]
        end = self.address[-4:]
        return f"{start}**{end}"

    def sign_message(self, message: str) -> str:
        return sign_message(message, self.eth_account)

    def tx_hash(self, chain: Chain, tx_hash: HexStr | str, value: Wei | int = None) -> str:
        tx_hash_link = chain.get_link_by_tx_hash(tx_hash)
        message = f"{self} {chain} {tx_hash_link}"
        if value is not None:
            message += f"\n\tSent: {from_wei(value, 'ether')} {chain.token.symbol}"
        return message

    def tx_receipt(self, chain: Chain, tx_receipt: TxReceipt, value: Wei | int = None) -> str:
        tx_hash = tx_receipt.transactionHash.hex()
        message = self.tx_hash(chain, tx_hash, value)
        tx_fee_wei = tx_receipt.gasUsed * tx_receipt.effectiveGasPrice
        tx_fee = from_wei(tx_fee_wei, "ether")
        message += f"\n\tFee: {tx_fee} {chain.token.symbol}"
        return message
