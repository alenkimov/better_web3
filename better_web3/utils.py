from eth_account.messages import encode_defunct
from eth_account.account import LocalAccount
from eth_typing import HexStr


def sign_message(account: LocalAccount, message: str) -> HexStr:
    message = encode_defunct(text=message)
    signed_message = account.sign_message(message)
    return HexStr(signed_message.signature.hex())
