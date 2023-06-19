from web3 import Web3

from better_web3 import Chain, TxSpeed

goerli = Chain("https://eth-goerli.public.blastapi.io")


def print_fees(tx_speed: TxSpeed):
    max_fee_per_gas, max_priority_fee_per_gas = goerli.estimate_eip1559_fees(tx_speed=tx_speed)
    max_fee_per_gas = Web3.from_wei(max_fee_per_gas, "gwei")
    max_priority_fee_per_gas = Web3.from_wei(max_priority_fee_per_gas, "gwei")
    print(f"maxFeePerGas: {max_fee_per_gas} gwei, MaxPriorityFeePerGas: {max_priority_fee_per_gas} gwei")


print_fees(TxSpeed.SLOWEST)
"""output:
maxFeePerGas: 99.226331394 gwei, MaxPriorityFeePerGas: 8.2E-8 gwei
"""

print_fees(TxSpeed.NORMAL)
"""output:
maxFeePerGas: 100.726331312 gwei, MaxPriorityFeePerGas: 1.5 gwei
"""

print_fees(TxSpeed.FASTEST)
"""output:
maxFeePerGas: 226.028500608 gwei, MaxPriorityFeePerGas: 126.802169296 gwei
"""

# If you want to convert a legacy tx to a EIP1559 one
# eip1559_tx_params = goerli.set_eip1559_fees(legacy_tx_params, tx_speed=TxSpeed.NORMAL)
