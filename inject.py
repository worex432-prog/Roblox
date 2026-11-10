"""Load a GitHub-hosted DLL through the project's existing Windows injector.

This uses a temporary DLL on disk: LoadLibraryW cannot load an HTTPS URL or
a Python byte buffer. The file may remain locked until the overlay is unloaded.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

MAX_BYTES = 32 * 1024 * 1024


def github_url(value):
    parts = urlsplit(value)
    if (parts.scheme != "https" or parts.hostname not in
            {"github.com", "raw.githubusercontent.com"} or
            parts.username or parts.password or parts.port not in (None, 443)):
        raise argparse.ArgumentTypeError(
            "Use an HTTPS GitHub release asset or raw.githubusercontent.com URL.")
    return value


def sha256_value(value):
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise argparse.ArgumentTypeError("SHA-256 must contain 64 hexadecimal characters.")
    return value.lower()


def validate_dll(data):
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError("The response is not a PE DLL (possibly a GitHub HTML page).")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if pe < 64 or pe + 26 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("Invalid PE header.")
    machine = struct.unpack_from("<H", data, pe + 4)[0]
    characteristics = struct.unpack_from("<H", data, pe + 22)[0]
    optional_magic = struct.unpack_from("<H", data, pe + 24)[0]
    if machine != 0x8664 or optional_magic != 0x20B or not characteristics & 0x2000:
        raise ValueError("Expected an x64 Windows DLL.")


def download(url, expected_hash):
    request = Request(url, headers={"User-Agent": "OpenGLOverlay-loader/1.0"})
    with urlopen(request, timeout=30) as response:
        if urlsplit(response.geturl()).scheme != "https":
            raise ValueError("Download redirected outside HTTPS.")
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("DLL exceeds the 32 MiB limit.")
    if hashlib.sha256(data).hexdigest() != expected_hash:
        raise ValueError("SHA-256 mismatch; injection cancelled.")
    validate_dll(data)
    return data


def find_injector(explicit):
    root = Path(__file__).resolve().parent
    candidates = [Path(explicit)] if explicit else [
        root / "outputs" / "injector.exe",
        root / "build" / "Release" / "injector.exe",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise FileNotFoundError("injector.exe not found; pass --injector PATH.")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Download a GitHub DLL to a temporary file and use injector.exe.",
        epilog="This is NOT a diskless loader. Unload the DLL before removing its temporary file.")
    parser.add_argument("target", help="Target PID or process name, e.g. javaw.exe")
    parser.add_argument("url", type=github_url, help="Direct public GitHub DLL download URL")
    parser.add_argument("--sha256", required=True, type=sha256_value,
                        help="SHA-256 of the exact DLL you published")
    parser.add_argument("--injector", help="Path to this project's x64 injector.exe")
    args = parser.parse_args(argv)
    temporary = None
    try:
        if os.name != "nt":
            raise OSError("This loader requires Windows.")
        if not args.target.strip() or args.target.startswith("-"):
            raise ValueError("Provide a PID or process name.")
        injector = find_injector(args.injector)
        data = download(args.url, args.sha256)
        temporary = Path(tempfile.mkdtemp(prefix="OpenGLOverlay-"))
        dll = temporary / "overlay.dll"
        dll.write_bytes(data)
        print("Temporary DLL: " + str(dll), flush=True)
        # No timeout here: the native injector owns its remote-thread wait.
        result = subprocess.run([str(injector), args.target, str(dll)], check=False)
        return result.returncode
    except (OSError, ValueError) as error:
        print("Error: " + str(error), file=sys.stderr)
        return 1
    finally:
        if temporary is not None:
            try:
                shutil.rmtree(temporary)
            except OSError:
                print("Temporary files remain at " + str(temporary) +
                      "; remove this folder after unloading the DLL.", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
