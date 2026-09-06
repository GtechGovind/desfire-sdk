#!/usr/bin/env python3
"""Create a DESFire C ABI XCFramework from explicit device and simulator libraries."""

from __future__ import annotations

import argparse
import pathlib
import shutil
import subprocess


def require_file(value: str, description: str) -> pathlib.Path:
    """Resolve one required input file before invoking Xcode build tooling."""
    path = pathlib.Path(value).resolve()
    if not path.is_file():
        raise SystemExit(f"{description} does not exist: {path}")
    return path


def architectures(library: pathlib.Path) -> set[str]:
    """Read exact Mach-O architectures from one static or dynamic library."""
    output = subprocess.check_output(["xcrun", "lipo", "-archs", str(library)], text=True)
    return set(output.split())


def main() -> None:
    """Validate slices and create a clean XCFramework using only caller-selected inputs."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device-library", required=True)
    parser.add_argument("--simulator-library", required=True)
    parser.add_argument("--headers", required=True)
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args()

    device = require_file(arguments.device_library, "device library")
    simulator = require_file(arguments.simulator_library, "simulator library")
    headers = pathlib.Path(arguments.headers).resolve()
    if not (headers / "desfire.h").is_file():
        raise SystemExit("headers must contain desfire.h and the desfire/ directory")
    if "arm64" not in architectures(device):
        raise SystemExit("device library must contain arm64")
    simulator_architectures = architectures(simulator)
    if "arm64" not in simulator_architectures or "x86_64" not in simulator_architectures:
        raise SystemExit("simulator library must contain arm64 and x86_64")

    output = pathlib.Path(arguments.output).resolve()
    if output.exists():
        shutil.rmtree(output)
    subprocess.run(
        [
            "xcrun", "xcodebuild", "-create-xcframework",
            "-library", str(device), "-headers", str(headers),
            "-library", str(simulator), "-headers", str(headers),
            "-output", str(output),
        ],
        check=True,
    )


if __name__ == "__main__":
    main()
