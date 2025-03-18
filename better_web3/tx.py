from eth_utils import from_wei
from web3.types import HexStr, Wei, TxReceipt

from .chain import Chain


def tx_hash_info(chain: Chain, address: str, tx_hash: HexStr | str, value: Wei | int = None) -> str:
    message = f"[{address}] ({chain}) {tx_hash}"
    for explorer, url in chain.tx_urls(tx_hash):
        message += f"\n\t[URL] {explorer.name} {url}"
    if value is not None:
        message += f"\n\tSent: {from_wei(value, "ether")} {chain.native_currency.symbol}"
    return message


def tx_receipt_info(chain: Chain, address: str, tx_receipt: TxReceipt, value: Wei | int = None) -> str:
    tx_hash = tx_receipt.transactionHash.hex()
    message = tx_hash_info(chain, address, tx_hash, value)
    tx_fee_wei = tx_receipt.gasUsed * tx_receipt.effectiveGasPrice
    tx_fee = from_wei(tx_fee_wei, "ether")
    message += f"\n\tFee: {tx_fee} {chain.native_currency.symbol}"
    return message
