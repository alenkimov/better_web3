from typing import Iterable
from hexbytes import HexBytes

import eth_abi
from eth_account.messages import encode_defunct
from eth_account.account import LocalAccount
from eth_utils import to_checksum_address, is_checksum_address
from eth_typing import AnyAddress, ChecksumAddress
from web3.contract.contract import ContractFunction
from web3.types import TxParams, Wei


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


def estimate_gas(
        contract_function: ContractFunction,
        *,
        from_: ChecksumAddress = None,
):
    tx_params: TxParams = {}
    if from_ is not None:
        tx_params["from"] = from_
    return contract_function.estimate_gas(tx_params)


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


def set_eip1559_fees(tx_params: TxParams, max_fee_per_gas: Wei = None,
                     max_priority_fee_per_gas: Wei = None,
                     ) -> TxParams:
    """
    Sets the transaction parameters in EIP1559 format.

    Args:
        tx_params (TxParams): The transaction parameters.
        max_fee_per_gas (Wei): The maximum fee per gas.
        max_priority_fee_per_gas (Wei): The maximum priority fee per gas.

    Returns:
        TxParams: The updated transaction parameters in EIP1559 format.

    Raises:
        ValueError: If EIP1559 is not supported.
    """
    tx_params = tx_params.copy()

    if "gasPrice" in tx_params:
        del tx_params["gasPrice"]

    tx_params["maxFeePerGas"] = max_fee_per_gas
    tx_params["maxPriorityFeePerGas"] = max_priority_fee_per_gas

    return tx_params
