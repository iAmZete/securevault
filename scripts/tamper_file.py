#!/usr/bin/env python3
"""Demo helper: flip one byte of an encrypted file on disk.

Used for test case INT-01 (file tampering). After running it, the file shows
"Failed" in the GUI, downloads are blocked and an ``integrity_failure`` event
appears in the Auditor log.

    python scripts/tamper_file.py --list
    python scripts/tamper_file.py <file_id>
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import create_app  # noqa: E402
from app.extensions import db  # noqa: E402
from app.models import StoredFile  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("file_id", nargs="?", type=int)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--offset", type=int, default=0, help="byte offset to flip (default 0)")
    args = parser.parse_args()

    app = create_app()
    with app.app_context():
        if args.list or args.file_id is None:
            for f in db.session.execute(db.select(StoredFile)).scalars():
                print(f"{f.id:>4}  owner={f.owner_id:<3} {f.storage_name}.enc  ({f.original_name})")
            return 0
        record = db.session.get(StoredFile, args.file_id)
        if record is None:
            print("No such file id.", file=sys.stderr)
            return 1
        path = Path(app.config["STORAGE_DIR"]) / f"{record.storage_name}.enc"
        data = bytearray(path.read_bytes())
        offset = min(max(args.offset, 0), len(data) - 1)
        data[offset] ^= 0x01
        path.write_bytes(bytes(data))
        print(f"Flipped one bit at offset {offset} of {path.name}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
