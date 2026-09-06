#!/usr/bin/env python3
"""Build the repository's pinned OpenSSL release for a GitHub Actions host."""

from __future__ import annotations

import argparse
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request


OPENSSL_VERSION = "3.5.8"
OPENSSL_SHA256 = "a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2"
OPENSSL_URL = (
    "https://github.com/openssl/openssl/releases/download/"
    f"openssl-{OPENSSL_VERSION}/openssl-{OPENSSL_VERSION}.tar.gz"
)


def checksum(path: Path) -> str:
    """Return the SHA-256 digest of one file without loading it into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    environment: dict[str, str] | None = None,
    log: Path | None = None,
) -> None:
    """Execute one argument vector and reveal a bounded build-log tail on failure."""
    print("Running:", " ".join(command), flush=True)
    if log is None:
        subprocess.run(command, cwd=cwd, env=environment, check=True)
        return
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8") as output:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            stdout=output,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
    if completed.returncode:
        with log.open(encoding="utf-8", errors="replace") as output:
            print("Last 200 OpenSSL build-log lines:", file=sys.stderr)
            print("".join(deque(output, maxlen=200)), file=sys.stderr)
        raise subprocess.CalledProcessError(completed.returncode, command)


def download(archive: Path) -> None:
    """Download the immutable upstream archive and atomically publish it."""
    archive.parent.mkdir(parents=True, exist_ok=True)
    temporary = archive.with_suffix(".download")
    temporary.unlink(missing_ok=True)
    request = urllib.request.Request(OPENSSL_URL, headers={"User-Agent": "desfire-sdk-ci"})
    with urllib.request.urlopen(request, timeout=120) as response, temporary.open("wb") as output:
        shutil.copyfileobj(response, output)
    temporary.replace(archive)


def extract(archive: Path, directory: Path) -> Path:
    """Extract a verified archive after rejecting traversal and special devices."""
    source = directory / f"openssl-{OPENSSL_VERSION}"
    if source.is_dir():
        return source
    directory.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as package:
        for member in package.getmembers():
            destination = (directory / member.name).resolve()
            if not destination.is_relative_to(directory.resolve()):
                raise RuntimeError("OpenSSL archive contains path traversal")
            if member.isdev():
                raise RuntimeError("OpenSSL archive contains a special device")
            if member.issym() or member.islnk():
                link_base = destination.parent if member.issym() else directory.resolve()
                if not (link_base / member.linkname).resolve().is_relative_to(directory.resolve()):
                    raise RuntimeError("OpenSSL archive link escapes the extraction directory")
        if sys.version_info >= (3, 12):
            package.extractall(directory, filter="fully_trusted")
        else:
            package.extractall(directory)
    return source


def openssl_target() -> str:
    """Map the current host architecture to an explicit OpenSSL target."""
    system = platform.system()
    machine = platform.machine().lower()
    targets = {
        ("Linux", "x86_64"): "linux-x86_64",
        ("Linux", "aarch64"): "linux-aarch64",
        ("Darwin", "x86_64"): "darwin64-x86_64-cc",
        ("Darwin", "arm64"): "darwin64-arm64-cc",
        ("Windows", "amd64"): "VC-WIN64A",
        ("Windows", "x86_64"): "VC-WIN64A",
    }
    try:
        return targets[(system, machine)]
    except KeyError as error:
        raise RuntimeError(f"Unsupported CI host: {system} {machine}") from error


def visual_studio_environment() -> Path:
    """Locate the Visual C++ developer environment through the installed vswhere tool."""
    installer = Path(os.environ.get("ProgramFiles(x86)", "")) / (
        "Microsoft Visual Studio/Installer/vswhere.exe"
    )
    if not installer.is_file():
        raise RuntimeError("vswhere.exe is unavailable on the Windows runner")
    installation = subprocess.check_output(
        [
            str(installer),
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationPath",
        ],
        text=True,
    ).strip()
    environment = Path(installation) / "Common7/Tools/VsDevCmd.bat"
    if not environment.is_file():
        raise RuntimeError("Visual Studio C++ developer environment is unavailable")
    return environment


def build_windows(
    source: Path, prefix: Path, configuration: list[str], jobs: int, log: Path
) -> None:
    """Build OpenSSL inside one MSVC developer command environment."""
    developer_environment = visual_studio_environment()
    configure = subprocess.list2cmdline(["perl", "Configure", *configuration])
    script = source.parent / "build-openssl.cmd"
    script.write_text(
        "@echo off\n"
        f'call "{developer_environment}" -arch=x64 -host_arch=x64\n'
        "if errorlevel 1 exit /b %errorlevel%\n"
        f'cd /d "{source}"\n'
        f"{configure}\n"
        "if errorlevel 1 exit /b %errorlevel%\n"
        "nmake /NOLOGO build_libs\n"
        "if errorlevel 1 exit /b %errorlevel%\n"
        "nmake /NOLOGO install_dev\n"
        "exit /b %errorlevel%\n",
        encoding="utf-8",
    )
    print(f"Building with {jobs} requested jobs; nmake executes the supported dependency graph", flush=True)
    run(["cmd.exe", "/d", "/s", "/c", str(script)], log=log)


def valid_install(prefix: Path, expected: dict[str, str]) -> bool:
    """Accept a cached install only when its provenance and required files match."""
    stamp = prefix / ".desfire-openssl.json"
    library = prefix / "lib" / ("libcrypto.lib" if platform.system() == "Windows" else "libcrypto.a")
    header = prefix / "include/openssl/opensslv.h"
    if not (stamp.is_file() and library.is_file() and header.is_file()):
        return False
    try:
        return json.loads(stamp.read_text(encoding="utf-8")) == expected
    except (OSError, ValueError):
        return False


def write_output(prefix: Path) -> None:
    """Expose the verified installation path to later workflow steps."""
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with Path(output).open("a", encoding="utf-8") as stream:
            stream.write(f"prefix={prefix.resolve()}\n")
    print(f"OpenSSL {OPENSSL_VERSION} ready at {prefix.resolve()}", flush=True)


def main() -> None:
    """Verify, build, and record the pinned host OpenSSL installation."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--jobs", type=int, default=min(os.cpu_count() or 2, 12))
    arguments = parser.parse_args()
    if arguments.jobs < 1:
        parser.error("--jobs must be positive")

    prefix = arguments.prefix.resolve()
    build_root = arguments.build_root.resolve()
    build_root.mkdir(parents=True, exist_ok=True)
    build_log = build_root / "build.log"
    archive = (arguments.archive or build_root / f"openssl-{OPENSSL_VERSION}.tar.gz").resolve()
    target = openssl_target()
    provenance = {
        "version": OPENSSL_VERSION,
        "source_sha256": OPENSSL_SHA256,
        "system": platform.system(),
        "machine": platform.machine().lower(),
        "target": target,
        "shared": False,
    }
    if valid_install(prefix, provenance):
        write_output(prefix)
        return

    if prefix.exists():
        shutil.rmtree(prefix)
    if not archive.is_file():
        download(archive)
    if checksum(archive) != OPENSSL_SHA256:
        raise RuntimeError("OpenSSL archive checksum differs from the pinned official release")
    source = extract(archive, build_root / "source")
    configuration = [
        target,
        "no-shared",
        "no-tests",
        "no-apps",
        "no-docs",
        "no-legacy",
        "no-fips",
        "no-module",
        "no-dso",
    ]
    if platform.system() != "Windows":
        configuration.append("-fPIC")
    configuration.extend([f"--prefix={prefix}", "--libdir=lib"])

    if platform.system() == "Windows":
        build_windows(source, prefix, configuration, arguments.jobs, build_log)
    else:
        environment = os.environ.copy()
        if platform.system() == "Darwin":
            environment.setdefault("MACOSX_DEPLOYMENT_TARGET", "14.0")
        run(
            ["perl", "Configure", *configuration],
            cwd=source,
            environment=environment,
            log=build_log,
        )
        run(
            ["make", f"-j{arguments.jobs}", "build_libs"],
            cwd=source,
            environment=environment,
            log=build_log,
        )
        run(["make", "install_dev"], cwd=source, environment=environment, log=build_log)

    prefix.mkdir(parents=True, exist_ok=True)
    (prefix / ".desfire-openssl.json").write_text(
        json.dumps(provenance, indent=2) + "\n", encoding="utf-8"
    )
    if not valid_install(prefix, provenance):
        raise RuntimeError("OpenSSL installation is incomplete after a successful build")
    write_output(prefix)


if __name__ == "__main__":
    main()
