from web3 import AsyncHTTPProvider

from .proxy import Proxy


class CustomAsyncHTTPProvider(AsyncHTTPProvider):
    def __init__(
            self,
            *args,
            proxy: Proxy = None,
            **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self._proxy = None
        self.set_proxy(proxy)

    def set_proxy(self, proxy: Proxy | None):
        if proxy:
            self._proxy = proxy
            self._request_kwargs["proxies"] = {'https': proxy.as_url, 'http': proxy.as_url}
