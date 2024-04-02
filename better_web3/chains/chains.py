import requests

from .models import CAIP2ChainData

from .. import Chain


def request_chains_data() -> dict[int: CAIP2ChainData]:
    """
    Возвращает словарь формата {ID сети: Информации о сети в формате CAIP-2}
    """
    response = requests.get("https://chainid.network/chains.json")
    return {chain_data["chainId"]: CAIP2ChainData(**chain_data) for chain_data in response.json()}


def chain_from_caip_2(
    chain_data: CAIP2ChainData,
    **chain_kwargs,
) -> Chain:
    target_rpc = None
    for rpc in chain_data.rpc_list:  # type: str
        if rpc.startswith("http") and "$" not in rpc:
            target_rpc = rpc
            break

    if not target_rpc:
        raise ValueError("Specify at least one http rpc")

    eip1559 = "EIP1559" in {feature.name for feature in chain_data.features} if chain_data.features else False

    return Chain(
        target_rpc,
        name=chain_data.name,
        short_name=chain_data.short_name,
        info_url=chain_data.info_url,
        native_currency=chain_data.native_currency,
        explorers=chain_data.explorers,
        eip1559=eip1559,
        **chain_kwargs,
    )
