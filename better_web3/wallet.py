from pathlib import Path

from eth_account.account import Account, LocalAccount
from eth_typing import ChecksumAddress

from better_web3.utils.eth import sign_message, to_checksum_addresses
from better_web3.utils.file import load_lines


def addresses_from_file(filepath: Path | str) -> list["ChecksumAddress"]:
    return to_checksum_addresses([address.strip() for address in load_lines(filepath)])


def wallets_from_file(filepath: Path | str) -> list["Wallet"]:
    return [Wallet.from_key(private_key) for private_key in load_lines(filepath)]


class Wallet:
    _number = 1

    def __init__(
            self,
            account: LocalAccount,
            *,
            name: str = None,
    ):
        self.account = account
        self.name = name
        self.number = Wallet._number
        Wallet._number += 1

    def __repr__(self):
        return f"Wallet(address={self.address})"

    def __str__(self) -> str:
        if self.name is not None: info = f"[{self.number:03}: {self.name}]"
        else: info = f"[{self.number:03}]"
        info += f" [{self.address}]"
        return info

    @classmethod
    def from_key(cls, private_key: str, name: str = None) -> "Wallet":
        account = Account.from_key(private_key)
        return cls(account, name=name)

    @classmethod
    def from_mnemonic(
            cls,
            mnemonic: str,
            passphrase: str = "",
            name: str = None,
    ) -> "Wallet":
        account = Account.from_key(mnemonic, passphrase)
        return cls(account, name=name)

    @property
    def private_key(self) -> str:
        return self.account.key.hex()

    @property
    def address(self) -> ChecksumAddress:
        return self.account.address

    def sign_message(self, message: str) -> str:
        return sign_message(message, self.account)
