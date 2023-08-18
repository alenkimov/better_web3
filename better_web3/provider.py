from web3 import AsyncHTTPProvider


class CustomAsyncHTTPProvider(AsyncHTTPProvider):
    def __init__(
            self,
            *args,
            proxy: str = None,
            **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self._proxy: str | None = None
        self.set_proxy(proxy)

    @property
    def proxy(self) -> str:
        return self._proxy

    def set_proxy(self, proxy_url: str | None):
        if proxy_url:
            self._proxy = proxy_url
            self._request_kwargs["proxies"] = {'https': proxy_url, 'http': proxy_url}
