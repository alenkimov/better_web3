from pydantic import BaseModel, Field
from typing import Literal

from web3.types import Wei


class NativeToken(BaseModel):
    symbol: str = "ETH"
    decimals: int = 18


class FeeParam(BaseModel):
    type_: Literal["multiplier", "gwei"] = Field(alias="type")
    value: float


class FeeSettings(BaseModel):
    max_fee_per_gas: FeeParam = FeeParam(type="multiplier", value=1.0)
    max_priority_fee_per_gas: FeeParam = FeeParam(type="multiplier", value=1.0)


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
