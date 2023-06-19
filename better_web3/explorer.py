from typing import Callable
import asyncio
import time
import json

import aiohttp
import requests
from eth_typing import HexStr, ChecksumAddress


class ExplorerError(RuntimeError):
    def __init__(self, message, data):
        super().__init__(message)

        self.data = data

    def __str__(self) -> str:
        return f"{super().__str__()}.\nReturned result: {self.data}"


class BaseExplorerAction:
    def __init__(self, module: "BaseExplorerModule", action: str):
        self.module = module
        self.action = action

    def _prepare_call_params(self, **params):
        params["module"] = str(self.module)
        params["action"] = self.action
        if self.module.explorer.api_key is not None:
            params["apikey"] = self.module.explorer.api_key
        return params

    @staticmethod
    def _handle_call(data):
        if data["status"] != "1":
            raise ExplorerError(data["message"], data["result"])
        return data["result"]

    def __call__(self, **params):
        params["module"] = str(self.module)
        params["action"] = self.action
        if self.module.explorer.api_key is not None:
            params["apikey"] = self.module.explorer.api_key

        if "apikey" not in params:
            # stupid throttling
            time.sleep(5)

        r = requests.get(self.module.explorer.api_url, params=params)
        result = r.json()
        if result["status"] != "1":
            raise ExplorerError(result["message"], result["result"])
        return result["result"]


class BaseExplorerModule:
    def __init__(self, explorer: "BaseExplorer", module: str):
        self.explorer = explorer
        self.name = module

    def __str__(self) -> str:
        return self.name

    def __getattr__(self, action: str) -> Callable:
        raise NotImplemented


class BaseExplorer:
    def __init__(self, url: str, api_url: str, api_key: str = None):
        self.url = url
        self.api_url = api_url
        self.api_key = api_key

    def __getattr__(self, module: str) -> BaseExplorerModule:
        raise NotImplemented

    def _handle_source_code(self, contact_data: dict) -> dict:
        abi = json.loads(contact_data["ABI"])
        if contact_data["Proxy"] == "1":
            implementation_info = self.contract.getsourcecode(
                address=contact_data["Implementation"]
            )[0]
            abi = json.loads(implementation_info["ABI"])
        return abi

    def fetch_abi(self, address: ChecksumAddress | str) -> dict:
        raise NotImplemented

    def get_link_by_tx_hash(self, tx_hash: HexStr):
        return f"{self.url}/tx/{tx_hash}"


class ExplorerAction(BaseExplorerAction):
    def __call__(self, **params):
        params = self._prepare_call_params(**params)

        if "apikey" not in params:
            # stupid rate limit
            time.sleep(5)

        response = requests.get(self.module.explorer.api_url, params=params)
        data = response.json()
        return self._handle_call(data)


class ExplorerModule(BaseExplorerModule):
    def __getattr__(self, action: str) -> Callable:
        return ExplorerAction(self, action)


class Explorer(BaseExplorer):
    def __getattr__(self, module: str) -> ExplorerModule:
        return ExplorerModule(self, module)

    def fetch_abi(self, address: ChecksumAddress | str) -> dict:
        contract_data = self.contract.getsourcecode(address=address)[0]
        return self._handle_source_code(contract_data)


class AsyncExplorerAction(BaseExplorerAction):
    async def __call__(self, **params):
        params = self._prepare_call_params(**params)

        if "apikey" not in params:
            # stupid rate limit
            await asyncio.sleep(5)

        response = await self.module.explorer.session.get(self.module.explorer.api_url, params=params)
        data = await response.json()
        return self._handle_call(data)


class AsyncExplorerModule(BaseExplorerModule):
    def __getattr__(self, action: str) -> Callable:
        return AsyncExplorerAction(self, action)


class AsyncExplorer(BaseExplorer):
    def __init__(self, session: aiohttp.ClientSession, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session = session

    def __getattr__(self, module: str) -> AsyncExplorerModule:
        return AsyncExplorerModule(self, module)

    async def fetch_abi(self, address: ChecksumAddress | str) -> dict:
        contract_data = await self.contract.getsourcecode(address=address)[0]
        return self._handle_source_code(contract_data)
