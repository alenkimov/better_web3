from better_web3 import Chain, TxSpeed

goerli = Chain("https://eth-goerli.public.blastapi.io")

base_fee, priority_fee = goerli.estimate_fee_eip1559(tx_speed=TxSpeed.NORMAL)
print(f"Base fee: {base_fee}, priority fee: {priority_fee}")

"""output:
Base fee: 36216, priority fee: 1500000000
"""

# If you want to convert a legacy tx to a EIP1559 one
# eip1559_tx_params = goerli.set_eip1559_fees(legacy_tx_params, tx_speed=TxSpeed.NORMAL)
