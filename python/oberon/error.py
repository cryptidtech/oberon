"""Error classes."""

from enum import IntEnum

class OberonErrorCode(IntEnum):
    SUCCESS = 0
    INPUT = 1
    SIGNING = 2
    WRAPPER = 99

class OberonError(Exception):
    def __init__(self, code: OberonErrorCode, message: str, extra: str = None):
        super().__init__(message)
        self.code = code
        self.extra = extra
