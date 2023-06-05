from typing import Union
from eth_typing import Hash32, HexStr
from hexbytes import HexBytes

TxHash = Union[Hash32, HexBytes, HexStr]
