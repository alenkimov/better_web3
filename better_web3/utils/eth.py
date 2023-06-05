from typing import Iterable

from eth_account.messages import encode_defunct
from eth_account.account import LocalAccount
import eth_abi
from eth_utils import to_checksum_address, is_checksum_address
from eth_typing import AnyAddress, ChecksumAddress


def sign_message(message: str, account: LocalAccount) -> str:
    message = encode_defunct(text=message)
    signed_message = account.sign_message(message)
    return signed_message.signature.hex()


def decode_string_or_bytes32(data: bytes) -> str:
    try:
        return eth_abi.decode(["string"], data)[0]
    except OverflowError:
        name = eth_abi.decode(["bytes32"], data)[0]
        end_position = name.find(b"\x00")
        if end_position == -1:
            return name.decode()
        else:
            return name[:end_position].decode()


def to_checksum_addresses(addresses: Iterable[AnyAddress or str]) -> list[AnyAddress]:
    return [address if is_checksum_address(address) else to_checksum_address(address)
            for address in addresses]
