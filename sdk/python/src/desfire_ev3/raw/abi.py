"""Generated ABI identity and stable operation lookup for expert integrations."""

from __future__ import annotations

import ctypes as ct
import os
from dataclasses import dataclass

from .operations_generated import ABI_VERSION, MANIFEST_SHA256, OPERATIONS


@dataclass(frozen=True)
class AbiOperation:
    """One stable canonical operation identity without protocol encoding."""

    identifier: int
    name: str
    symbol: str
    surface: str


def operations() -> tuple[AbiOperation, ...]:
    """Return all manifest operations in stable identifier order."""
    return tuple(
        AbiOperation(identifier, name, symbol, surface)
        for identifier, (name, symbol, surface) in sorted(OPERATIONS.items())
    )


def verify_library(path: str | os.PathLike[str]) -> None:
    """Reject a native library whose ABI revision or canonical manifest differs."""
    native = ct.CDLL(os.path.abspath(os.fspath(path)))
    native.df_abi_version.argtypes = []
    native.df_abi_version.restype = ct.c_uint32
    native.df_manifest_sha256.argtypes = []
    native.df_manifest_sha256.restype = ct.c_char_p
    if native.df_abi_version() != ABI_VERSION:
        raise RuntimeError("The native DESFire library has an incompatible ABI version")
    digest = native.df_manifest_sha256()
    if digest is None or digest.decode("ascii", errors="replace") != MANIFEST_SHA256:
        raise RuntimeError("The native DESFire library has an incompatible operation manifest")


__all__ = ["ABI_VERSION", "AbiOperation", "MANIFEST_SHA256", "operations", "verify_library"]
