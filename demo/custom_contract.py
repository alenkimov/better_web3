from typing import Iterable
from pprint import pformat

from web3.contract.contract import ContractFunction
from web3.types import Wei, ChecksumAddress, TxReceipt
from eth_account import Account
from eth_utils import from_wei, to_wei

from better_web3 import Chain
from better_web3.contract import Contract
from better_web3.utils import link_by_tx_hash, load_json, to_checksum_addresses

from get_balances import print_balances


class Disperse(Contract):
    def disperse_ether(
            self,
            recipients: Iterable[ChecksumAddress | str],
            values: Iterable[Wei | int],
    ) -> ContractFunction:
        """
        disperseEther(address[] recipients, uint256[] values)
        """
        return self.functions.disperseEther(recipients, values)


def print_goerli_tx_hash(tx_hash: str):
    print(f"tx: {link_by_tx_hash('https://goerli.etherscan.io', tx_hash)}")


def print_tx_receipt(tx_receipt: TxReceipt):
    print(f"tx_receipt:")
    print(pformat(dict(tx_receipt)))


def get_and_print_balances(addresses):
    eth_balances = goerli.batch_request.balances(addresses, raise_exceptions=False)
    print_balances(eth_balances, goerli.token.symbol)


if __name__ == '__main__':
    goerli = Chain("https://eth-goerli.public.blastapi.io", symbol="gETH")

    disperse_contract_address = "0xD152f549545093347A162Dce210e7293f1452150"
    disperse_abi = load_json("disperse_abi.json")
    disperse = Disperse(goerli, disperse_contract_address, disperse_abi)

    private_key = "..."
    account = Account.from_key(private_key)

    values = [to_wei(0.01, "ether")] * 2
    total_value = sum(values)
    recipients = to_checksum_addresses(
        [
            "0x...",
            "0x...",
        ]
    )
    get_and_print_balances(recipients)
    """output
    [001] [0xd87Fa8ac81834c6625519589C38Cb54899F1FBA5] gETH 0.11
    [002] [0xc278c6B61C33A97e39cE5603Caa8A0235839B2b0] gETH 0.11
    """

    print(f"Transferring {goerli.token.symbol} {from_wei(total_value, 'ether')} from {account.address} to:")
    for recipient, value in zip(recipients, values):
        print(f" ==[{goerli.token.symbol} {from_wei(value, 'ether')}]==>> {recipient}")
    """output
    Transferring gETH 0.02 from 0x780afe4a82Ed3B46eA6bA94a1BB8F7b977298722 to:
     ==[gETH 0.01]==>> 0xd87Fa8ac81834c6625519589C38Cb54899F1FBA5
     ==[gETH 0.01]==>> 0xc278c6B61C33A97e39cE5603Caa8A0235839B2b0
    """

    disperse_ether_fn = disperse.disperse_ether(recipients, values)
    tx = goerli.build_tx(disperse_ether_fn, from_=account.address, value=total_value)

    tx_hash = goerli.sign_and_send_tx(account, tx)
    print_goerli_tx_hash(tx_hash)
    """output
    tx: https://goerli.etherscan.io/tx/0xdb7a3a03c49752aabb96207508269493eb35762249ad1b4e90a97685cb899571
    """

    tx_receipt = goerli.wait_for_tx_receipt(tx_hash)
    # print_tx_receipt(tx_receipt)

    get_and_print_balances(recipients)
    """output
    [001] [0xd87Fa8ac81834c6625519589C38Cb54899F1FBA5] gETH 0.12
    [002] [0xc278c6B61C33A97e39cE5603Caa8A0235839B2b0] gETH 0.12
    """
