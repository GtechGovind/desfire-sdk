"""Run the published NXP AES-128 diversification vector through the Python SDK."""

from __future__ import annotations

import os

from desfire_ev3 import Aes128Key, Offline


def main() -> None:
    """Load the explicit native library, derive a key, and wipe owned key objects."""
    offline = Offline(os.environ["DESFIRE_LIBRARY"])
    master = Aes128Key(bytes.fromhex("00112233445566778899aabbccddeeff"))
    derived = offline.derive_nxp_aes128(
        master,
        bytes.fromhex("04782e21801d803042f54e585020416275"),
    )
    try:
        assert derived.snapshot().hex() == "a8dd63a3b89d54b37ca802473fda9175"
    finally:
        derived.close()
        master.close()


if __name__ == "__main__":
    main()
