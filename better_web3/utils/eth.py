from pathlib import Path
from typing import Iterable
from hexbytes import HexBytes

import eth_abi
from eth_account.messages import encode_defunct
from eth_account.account import LocalAccount
from eth_utils import to_checksum_address
from eth_typing import AnyAddress, ChecksumAddress
from web3.types import BlockParams, BlockIdentifier, HexStr

from .file import load_lines

BLOCK_PARAMS = ("latest", "earliest", "pending", "safe", "finalized")


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


def to_checksum_addresses(addresses: Iterable[AnyAddress or str]) -> list[ChecksumAddress]:
    return [to_checksum_address(address) for address in addresses]


def addresses_from_file(filepath: Path | str) -> list["ChecksumAddress"]:
    return to_checksum_addresses([address.strip() for address in load_lines(filepath)])


GAS_CALL_DATA_ZERO_BYTE = 4
GAS_CALL_DATA_BYTE = 16  # 68 before Istanbul


def estimate_data_gas(data: bytes):
    if isinstance(data, str):
        data = HexBytes(data)

    gas = 0
    for byte in data:
        if not byte:
            gas += GAS_CALL_DATA_ZERO_BYTE
        else:
            gas += GAS_CALL_DATA_BYTE
    return gas


def hex_block_identifier(block_identifier: BlockIdentifier) -> HexStr | BlockParams:
    if block_identifier in BLOCK_PARAMS:
        return block_identifier
    elif isinstance(block_identifier, int):
        block_identifier = hex(block_identifier)
    elif isinstance(block_identifier, bytes):
        block_identifier = HexBytes(block_identifier).hex()
    return HexStr(block_identifier)
