from eth_utils import from_wei

from better_web3 import Chain, JSONRPCException
from better_web3.utils.eth import to_checksum_addresses


def print_balances(balances, token_symbol: str):
    for i, balance_data in enumerate(balances, start=1):
        address = balance_data["address"]
        balance = balance_data["balance"]
        print(f"[{i:03}] [{address}] ", end="")
        if not isinstance(balance, JSONRPCException):
            balance = from_wei(balance, "ether")
            print(f"{token_symbol} {round(balance, 2)}")
        else:
            print(balance)


if __name__ == '__main__':
    with open("addresses.txt", "r") as file:
        addresses = to_checksum_addresses([address.strip() for address in file.readlines()])

    goerli = Chain("https://eth-goerli.public.blastapi.io", symbol="gETH", batch_request_size=15)

    eth_balances = goerli.batch_request.balances(addresses, raise_exceptions=False)
    print_balances(eth_balances, goerli.token.symbol)
    """output:
    [001] [0x780afe4a82Ed3B46eA6bA94a1BB8F7b977298722] gETH 17.72
    [002] [0xB4FBF271143F4FBf7B91A5ded31805e42b2208d6] gETH 976015.51
    ...
    """

    weth = goerli.erc20("0xb4fbf271143f4fbf7b91a5ded31805e42b2208d6")
    weth_balances = weth.get_balances(addresses, raise_exceptions=False)
    print_balances(weth_balances, weth.symbol)
    """output:
    [001] [0x780afe4a82Ed3B46eA6bA94a1BB8F7b977298722] WETH 1.20
    [002] [0xB4FBF271143F4FBf7B91A5ded31805e42b2208d6] WETH 47.35
    ...
    """
