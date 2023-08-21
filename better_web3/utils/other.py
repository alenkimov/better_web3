from typing import Iterable
from itertools import islice


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
