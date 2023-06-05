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
