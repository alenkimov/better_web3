from typing import NamedTuple, Optional

from web3.types import TxParams


class EthereumTxSent(NamedTuple):
    tx_hash: bytes
    tx: TxParams
    contract_address: Optional[str]


class Erc20Info(NamedTuple):
    name: str
    symbol: str
    decimals: int


class Erc721Info(NamedTuple):
    name: str
    symbol: str
