from eth_utils import to_wei

from ._paths import SCRIPT_DIR
from .chain import Chain
from .utils.file import load_toml

CHAINS_FILEPATH = SCRIPT_DIR / "chains.toml"
CHAINS_DATA = load_toml(CHAINS_FILEPATH)


def load_chains(chains_data: dict, ensure_chain_id=True, **chain_kwargs) -> dict[int: Chain]:
    chains: dict[int: Chain] = {}
    for net_mode, id_to_chain_data in chains_data.items():
        is_testnet = True if net_mode == "testnet" else False
        for chain_id, chain_data in id_to_chain_data.items():
            chain_id = int(chain_id)
            if "gas_price" in chain_data:
                chain_data["gas_price"] = to_wei(chain_data["gas_price"], "gwei")
            chain = Chain(**chain_data, is_testnet=is_testnet, **chain_kwargs)
            if ensure_chain_id and chain.chain_id == chain_id or not ensure_chain_id:
                chains[chain_id] = chain
    return chains
