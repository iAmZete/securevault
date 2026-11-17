"""Run SecureVault locally over HTTPS.

    python run.py                 # https://127.0.0.1:5443
    flask --app run.py <command>  # management commands (init, create-admin, ...)
"""
from __future__ import annotations

import os
import sys

from app import create_app

app = create_app()

if __name__ == "__main__":
    cert = app.config["TLS_CERT_FILE"]
    key = app.config["TLS_KEY_FILE"]
    if not (cert.exists() and key.exists()):
        sys.exit(
            "TLS certificate not found.\n"
            "Generate a local self-signed certificate first:\n"
            "    python scripts/generate_cert.py\n"
            f"(expected {cert} and {key})"
        )
    host = os.environ.get("SECUREVAULT_HOST", "127.0.0.1")
    port = int(os.environ.get("SECUREVAULT_PORT", "5443"))
    # debug=False: the Werkzeug debugger must never be exposed.
    app.run(host=host, port=port, ssl_context=(str(cert), str(key)), debug=False)
