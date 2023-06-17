from eth_utils import from_wei
from web3.types import Wei, ChecksumAddress

from better_web3 import Chain
from better_web3.utils import to_checksum_addresses


goerli = Chain("https://eth-goerli.public.blastapi.io")

weth = goerli.erc20("0xb4fbf271143f4fbf7b91a5ded31805e42b2208d6")

addresses = to_checksum_addresses(
    [
        "0x780afe4a82Ed3B46eA6bA94a1BB8F7b977298722",
        "0xb4fbf271143f4fbf7b91a5ded31805e42b2208d6",
    ]
)


def print_balances(balances: dict[ChecksumAddress: Wei], token_symbol: str):
    eth_balances = {address: from_wei(balance, "ether") for address, balance in balances.items()}
    for i, (address, balance) in enumerate(eth_balances.items(), start=1):
        print(f"[{i}] [{address}] {balance:.2f} {token_symbol}")


eth_balances_wei = goerli.get_balances(addresses)
print_balances(eth_balances_wei, "ETH")
"""output:
[1] [0x780afe4a82Ed3B46eA6bA94a1BB8F7b977298722] 17.72 ETH
[2] [0xB4FBF271143F4FBf7B91A5ded31805e42b2208d6] 1013680.97 ETH
"""

weth_balances_wei = weth.get_balances(addresses)
print_balances(weth_balances_wei, weth.get_symbol())
"""output:
[1] [0x780afe4a82Ed3B46eA6bA94a1BB8F7b977298722] 1.20 WETH
[2] [0xB4FBF271143F4FBf7B91A5ded31805e42b2208d6] 47.35 WETH
"""
