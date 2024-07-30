from json import dumps


class LocalSendException(Exception):
    ...


class LSPrepareUploadException(LocalSendException):
    CODE: int
    BODY: str


class AlreadyFinished(LSPrepareUploadException):
    CODE = 204
    BODY = ""


class InvalidBody(LSPrepareUploadException):
    CODE = 400
    BODY = dumps({"message": "Invalid body."})


class InvalidPin(LSPrepareUploadException):
    CODE = 401
    BODY = dumps({"message": "Invalid pin."})


PinRequired = InvalidPin


class Rejected(LSPrepareUploadException):
    CODE = 403
    BODY = dumps({"message": "Rejected."})


class BlockedByAnotherSession(LSPrepareUploadException):
    CODE = 409
    BODY = dumps({"message": "Upload blocked by another session."})


class TooManyRequests(LSPrepareUploadException):
    CODE = 429
    BODY = dumps({"message": "Too many requests."})
