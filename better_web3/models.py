from pydantic import BaseModel


class Explorer(BaseModel):
    name: str
    url: str
    standard: str
    # icon: str | None = None


class NativeCurrency(BaseModel):
    name: str = "Ether"
    symbol: str = "ETH"
    decimals: int = 18
