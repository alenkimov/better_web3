from pydantic import BaseModel, Field


class Explorer(BaseModel):
    name: str
    url: str
    standard: str
    # icon: str | None = None


class NativeCurrency(BaseModel):
    name: str = "Ether"
    symbol: str = "ETH"
    decimals: int = 18


class Feature(BaseModel):
    name: str


class CAIP2ChainData(BaseModel):
    name: str
    chain: str
    rpc_list: list[str] = Field(alias="rpc")
    explorers: list[Explorer] = Field(default_factory=list)
    # faucets: list[str] = Field(default_factory=list)
    native_currency: NativeCurrency = Field(alias="nativeCurrency")
    features: list[Feature] | None = None
    info_url: str = Field(alias="infoURL")
    short_name: str = Field(alias="shortName")
    chain_id: int = Field(alias="chainId")
    # network_id: int = Field(alias="networkId")
    # icon: str | None = None
    # slip44: int | None = None
    # ens: dict | None = None
