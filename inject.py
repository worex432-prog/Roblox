"""Load the overlay DLL straight into a running process memory.

The DLL is never written to disk. It is read from a local file (or downloaded
into memory when --url is used) and piped to injector.exe --stdin, which maps
it into the target by hand and calls its entry point.

Usage:
    python inject.py javaw.exe
    python inject.py javaw.exe --dll payload.dll
    python inject.py javaw.exe --url https://raw.githubusercontent.com/.../payload.dll --sha256 <64 hex>
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
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
        raise ValueError("The payload is not a PE DLL (possibly a GitHub HTML page).")
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
    if expected_hash and hashlib.sha256(data).hexdigest() != expected_hash:
        raise ValueError("SHA-256 mismatch; injection cancelled.")
    validate_dll(data)
    return data


def find_injector(explicit):
    root = Path(__file__).resolve().parent
    candidates = [Path(explicit)] if explicit else [
        root / "injector.exe",
        root / "outputs" / "injector.exe",
        root / "build" / "Release" / "injector.exe",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise FileNotFoundError("injector.exe not found; pass --injector PATH.")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Map payload.dll into a target process without writing the DLL to disk.",
        epilog="The DLL bytes are streamed to injector.exe on stdin and mapped in memory.")
    parser.add_argument("target", help="Target PID or process name, e.g. javaw.exe")
    parser.add_argument("--dll", help="Local DLL to load (default: payload.dll next to this script)")
    parser.add_argument("--url", type=github_url, help="Optional HTTPS URL to download the DLL into memory")
    parser.add_argument("--sha256", type=sha256_value, help="SHA-256 of the downloaded DLL (with --url)")
    parser.add_argument("--injector", help="Path to injector.exe")
    args = parser.parse_args(argv)
    try:
        if os.name != "nt":
            raise OSError("This loader requires Windows.")
        if not args.target.strip() or args.target.startswith("-"):
            raise ValueError("Provide a PID or process name.")
        injector = find_injector(args.injector)

        if args.url:
            data = download(args.url, args.sha256)
        else:
            path = Path(args.dll) if args.dll else Path(__file__).resolve().parent / "payload.dll"
            if not path.is_file():
                raise FileNotFoundError("DLL not found: " + str(path) + " (pass --dll PATH)")
            data = path.read_bytes()
            if len(data) > MAX_BYTES:
                raise ValueError("DLL exceeds the 32 MiB limit.")
            validate_dll(data)
        print("Loaded " + str(len(data)) + " bytes from memory; no DLL file is written.", flush=True)

        # The native injector owns its remote-thread wait, so no timeout here.
        result = subprocess.run([str(injector), args.target, "--stdin"],
                                input=data, check=False)
        return result.returncode
    except (OSError, ValueError) as error:
        print("Error: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
