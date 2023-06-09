class ChainException(ValueError):
    pass


class ChainIdIsRequired(ChainException):
    pass


class TransactionAlreadyImported(ChainException):
    pass


class ReplacementTransactionUnderpriced(ChainException):
    pass


class TransactionQueueLimitReached(ChainException):
    pass


class FromAddressNotFound(ChainException):
    pass


class InvalidNonce(ChainException):
    pass


class NonceTooLow(InvalidNonce):
    pass


class NonceTooHigh(InvalidNonce):
    pass


class InsufficientFunds(ChainException):
    pass


class SenderAccountNotFoundInNode(ChainException):
    pass


class UnknownAccount(ChainException):
    pass


class GasLimitExceeded(ChainException):
    pass


class TransactionGasPriceTooLow(ChainException):
    pass


class BatchCallException(ChainException):
    pass


class BatchCallFunctionFailed(BatchCallException):
    pass


error_msg_to_exception: dict[str, ChainException] = {
    "EIP-155": ChainIdIsRequired,
    "Transaction with the same hash was already imported": TransactionAlreadyImported,
    # https://github.com/ethereum/go-ethereum/blob/eaccdba4ab310e3fb98edbc4b340b5e7c4d767fd/core/tx_pool.go#L72
    "replacement transaction underpriced": ReplacementTransactionUnderpriced,
    # https://github.com/openethereum/openethereum/blob/f1dc6821689c7f47d8fd07dfc0a2c5ad557b98ec/crates/rpc/src/v1/helpers/errors.rs#L374
    "There is another transaction with same nonce in the queue": ReplacementTransactionUnderpriced,
    "There are too many transactions in the queue. Your transaction was dropped due to limit. Try increasing "
    # https://github.com/openethereum/openethereum/blob/f1dc6821689c7f47d8fd07dfc0a2c5ad557b98ec/crates/rpc/src/v1/helpers/errors.rs#L380
    "the fee": TransactionQueueLimitReached,
    # https://github.com/ethereum/go-ethereum/blob/eaccdba4ab310e3fb98edbc4b340b5e7c4d767fd/core/tx_pool.go#L68
    "txpool is full": TransactionQueueLimitReached,
    # https://github.com/ethereum/go-ethereum/blob/eaccdba4ab310e3fb98edbc4b340b5e7c4d767fd/core/tx_pool.go#L64
    "transaction underpriced": TransactionGasPriceTooLow,
    # https://github.com/openethereum/openethereum/blob/f1dc6821689c7f47d8fd07dfc0a2c5ad557b98ec/crates/rpc/src/v1/helpers/errors.rs#L386
    "Transaction gas price is too low": TransactionGasPriceTooLow,
    "from not found": FromAddressNotFound,
    "correct nonce": InvalidNonce,
    # https://github.com/ethereum/go-ethereum/blob/bbfb1e4008a359a8b57ec654330c0e674623e52f/core/error.go#L46
    "nonce too low": NonceTooLow,
    # https://github.com/ethereum/go-ethereum/blob/bbfb1e4008a359a8b57ec654330c0e674623e52f/core/error.go#L46
    "nonce too high": NonceTooHigh,
    # https://github.com/openethereum/openethereum/blob/f1dc6821689c7f47d8fd07dfc0a2c5ad557b98ec/crates/rpc/src/v1/helpers/errors.rs#L389
    "insufficient funds": InsufficientFunds,
    "doesn't have enough funds": InsufficientFunds,
    "sender account not recognized": SenderAccountNotFoundInNode,
    "unknown account": UnknownAccount,
    # Geth
    "exceeds block gas limit": GasLimitExceeded,
    # https://github.com/openethereum/openethereum/blob/f1dc6821689c7f47d8fd07dfc0a2c5ad557b98ec/crates/rpc/src/v1/helpers/errors.rs#L392
    "exceeds current gas limit": GasLimitExceeded,
}
