"""Run the Swift host suite with explicit canonical C header and native-library paths."""

import argparse
from pathlib import Path
import subprocess


def main() -> None:
    """Configure SwiftPM's system C module and loader without copying protocol sources."""
    package = Path(__file__).resolve().parents[1]
    root = package.parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-build", type=Path, default=root / "build/ev3")
    parser.add_argument(
        "--scratch-path", type=Path, default=root / "build/apple-swift-tests",
        help="SwiftPM build directory; defaults outside the package source tree",
    )
    options, swift_arguments = parser.parse_known_args()
    library = options.native_build.resolve() / "c-api"
    subprocess.run([
        "swift", "test", "--package-path", str(package),
        "--scratch-path", str(options.scratch_path.resolve()),
        "-Xcc", "-I" + str(root / "c-api/include"),
        "-Xlinker", "-L" + str(library),
        "-Xlinker", "-rpath", "-Xlinker", str(library),
        *swift_arguments,
    ], check=True)


if __name__ == "__main__":
    main()
