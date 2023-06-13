import requests  # TODO не хватает асинхронной реализации AsyncGasStation на aiohttp
from web3 import Web3

from .models import GasData


class GasStation:
    def __init__(self, url: str):
        self.url = url

    def get_gas_data(self) -> GasData:
        response = requests.get(self.url)
        data: dict = response.json()
        for speed in ("safeLow", "standard", "fast"):
            data[speed]["maxFee"] = Web3.to_wei(data[speed]["maxFee"], "gwei")
            data[speed]["maxPriorityFee"] = Web3.to_wei(data[speed]["maxPriorityFee"], "gwei")
        data["estimatedBaseFee"] = Web3.to_wei(data["estimatedBaseFee"], "ether")
        return GasData(**data)
