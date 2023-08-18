import json
from typing import Iterable
from itertools import islice

from eth_typing import HexStr


def chunks(elements: Iterable, n: int) -> Iterable[list]:
    """
    :param elements: Iterable
    :param n: Number per chunk
    :return: Yield successive n-sized chunks from elements
    """
    it = iter(elements)
    while True:
        chunk = list(islice(it, n))
        if not chunk:
            return
        yield chunk


def link_by_tx_hash(explorer_url: str, tx_hash: HexStr | str):
    return f"{explorer_url}/tx/{tx_hash}"


def to_json(obj) -> str:
    return json.dumps(obj, separators=(',', ':'), ensure_ascii=True)
