from eth_account.messages import encode_defunct
from eth_account.account import LocalAccount
from eth_typing import HexStr


def sign_message(message: str, account: LocalAccount) -> str:
    message = encode_defunct(text=message)
    signed_message = account.sign_message(message)
    return signed_message.signature.hex()


def tx_url(explorer_url: str, tx_hash: HexStr | str):
    return f"{explorer_url}/tx/{tx_hash}"
