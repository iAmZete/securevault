#!/usr/bin/env python3
"""Generate the 256-bit SecureVault master key (key-encryption key).

By default the key is written to secrets/master.key with mode 600. Set
SECUREVAULT_MASTER_KEY_FILE (or pass --out) to keep it somewhere outside the
project directory entirely, e.g. ~/.securevault/master.key.

The key is never committed to Git (secrets/ and *.key are git-ignored).
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.security.crypto import MasterKeyError, generate_master_key_file  # noqa: E402


def main() -> int:
    default = Path(os.environ.get("SECUREVAULT_MASTER_KEY_FILE", ROOT / "secrets" / "master.key"))
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=default)
    args = parser.parse_args()
    try:
        path = generate_master_key_file(args.out.expanduser())
    except MasterKeyError as exc:
        print(exc, file=sys.stderr)
        return 1
    print(f"Master key written to {path} (mode 600). Back it up securely; losing it makes "
          "every stored file unrecoverable.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
