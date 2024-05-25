from typing import Iterable
from functools import lru_cache

import requests

from .models import CAIP2ChainData
from . import Chain


@lru_cache
def request_chains_caip_2_data() -> dict[int: CAIP2ChainData]:
    """
    :returns: {chain ID: CAIP-2 chain data}
    """
    response = requests.get("https://chainid.network/chains.json")
    data = response.json()
    return {chain_data["chainId"]: CAIP2ChainData(**chain_data) for chain_data in data}


def _chain_from_caip_2_data(
    chain_caip2_data: CAIP2ChainData,
    **chain_kwargs,
) -> Chain:
    target_rpc = None
    for rpc in chain_caip2_data.rpc_list:  # type: str
        if rpc.startswith("http") and "$" not in rpc:
            target_rpc = rpc
            break

    if not target_rpc:
        raise ValueError("No http rpc")

    eip1559 = "EIP1559" in {feature.name for feature in chain_caip2_data.features} if chain_caip2_data.features else False

    return Chain(
        target_rpc,
        name=chain_caip2_data.name,
        short_name=chain_caip2_data.short_name,
        info_url=chain_caip2_data.info_url,
        native_currency=chain_caip2_data.native_currency,
        explorers=chain_caip2_data.explorers,
        eip1559=eip1559,
        **chain_kwargs,
    )


def get_chain(chain_id: int, **chain_kwargs) -> Chain:
    chains_caip2_data = request_chains_caip_2_data()
    chain_caip2_data = chains_caip2_data[chain_id]

    if "rpc" in chain_kwargs:
        chains_caip2_data.rpc_list.insert(0, chain_kwargs.pop("rpc"))

    return _chain_from_caip_2_data(chain_caip2_data, **chain_kwargs)


def get_chains(chain_ids: Iterable[int]) -> list[Chain]:
    return [get_chain(chain_id) for chain_id in chain_ids]
