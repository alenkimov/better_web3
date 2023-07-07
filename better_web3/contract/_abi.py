from ..utils.file import load_json
from ._paths import ABI_DIR


MULTICALL_V3_ABI = load_json(ABI_DIR / "multicall_v3.json")
DISPERSE_ABI     = load_json(ABI_DIR / "disperse.json")
ERC1155_ABI      = load_json(ABI_DIR / "erc1155.json")
ERC721_ABI       = load_json(ABI_DIR / "erc721.json")
ERC20_ABI        = load_json(ABI_DIR / "erc20.json")
