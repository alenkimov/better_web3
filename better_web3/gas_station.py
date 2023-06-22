import aiohttp
import requests
from pydantic import BaseModel, Field
from web3 import Web3
from web3.types import Wei


class SafeLow(BaseModel):
    max_priority_fee: Wei = Field(..., alias='maxPriorityFee')
    max_fee: Wei = Field(..., alias='maxFee')


class Standard(BaseModel):
    max_priority_fee: Wei = Field(..., alias='maxPriorityFee')
    max_fee: Wei = Field(..., alias='maxFee')


class Fast(BaseModel):
    max_priority_fee: Wei = Field(..., alias='maxPriorityFee')
    max_fee: Wei = Field(..., alias='maxFee')


class GasData(BaseModel):
    safe_low: SafeLow = Field(..., alias='safeLow')
    standard: Standard
    fast: Fast
    estimated_base_fee: Wei = Field(..., alias='estimatedBaseFee')
    block_time: int = Field(..., alias='blockTime')
    block_number: int = Field(..., alias='blockNumber')


class BaseGasStation:
    def __init__(self, url: str):
        self.url = url

    @staticmethod
    def _handle_gas_data(gas_data: dict) -> GasData:
        for speed in ("safeLow", "standard", "fast"):
            gas_data[speed]["maxFee"] = Web3.to_wei(gas_data[speed]["maxFee"], "gwei")
            gas_data[speed]["maxPriorityFee"] = Web3.to_wei(gas_data[speed]["maxPriorityFee"], "gwei")
        gas_data["estimatedBaseFee"] = Web3.to_wei(gas_data["estimatedBaseFee"], "ether")
        return GasData(**gas_data)

    def get_gas_data(self) -> GasData:
        raise NotImplemented


class GasStation(BaseGasStation):
    def get_gas_data(self) -> GasData:
        response = requests.get(self.url)
        data = response.json()
        return self._handle_gas_data(data)


class AsyncGasStation(BaseGasStation):
    def __init__(self, session: aiohttp.ClientSession, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session = session

    async def get_gas_data(self) -> GasData:
        response = await self.session.get(self.url)
        data = await response.json()
        return self._handle_gas_data(data)
