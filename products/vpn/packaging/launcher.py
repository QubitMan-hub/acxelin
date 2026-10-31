"""Acxelin VPN as a packaged app. With no arguments it is the desktop app; with arguments it is the acxelin-vpn command, which
is also how the desktop app starts its background service. OpenSSL 3.5 ships inside the package."""
import os
import sys
from pathlib import Path

bundled = Path(getattr(sys, "_MEIPASS", Path(__file__).parent)) / "openssl"
if bundled.is_dir():
    os.environ["ACXELIN_OPENSSL"] = str(bundled)  # assigned, not defaulted: a folder planted in the user's environment must not win

from acxelin_vpn.cli import main  # noqa: E402

if __name__ == "__main__":
    main(sys.argv[1:] or ["desktop"])
