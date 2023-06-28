from eth_account.account import Account, LocalAccount

from better_web3.utils.eth import sign_message


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

    @staticmethod
    def from_key(private_key: str, name: str = None) -> "Wallet":
        account = Account.from_key(private_key)
        return Wallet(account, name=name)

    @staticmethod
    def from_mnemonic(
            mnemonic: str,
            passphrase: str = "",
            name: str = None,
    ) -> "Wallet":
        account = Account.from_key(mnemonic, passphrase)
        return Wallet(account, name=name)

    @property
    def private_key(self) -> str:
        return self.account.key.hex()

    @property
    def address(self) -> str:
        return self.account.address

    def sign_message(self, message: str) -> str:
        return sign_message(message, self.account)
