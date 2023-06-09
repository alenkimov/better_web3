from better_web3 import Chain, TxSpeed

goerli = Chain("https://eth-goerli.public.blastapi.io")

max_fee_per_gas, max_priority_fee_per_gas = goerli.estimate_eip1559_fees(tx_speed=TxSpeed.FASTEST)
print(f"maxFeePerGas: {max_fee_per_gas} Wei, MaxPriorityFeePerGas: {max_priority_fee_per_gas} Wei")

"""output:
maxFeePerGas: 100000000001 Wei, MaxPriorityFeePerGas: 99999999945 Wei
"""

# If you want to convert a legacy tx to a EIP1559 one
# eip1559_tx_params = goerli.set_eip1559_fees(legacy_tx_params, tx_speed=TxSpeed.NORMAL)
