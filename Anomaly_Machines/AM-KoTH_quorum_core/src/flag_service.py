#!/usr/bin/env python3
"""
QUORUM Core — internal flag-update webhook service.

Listens on port 8081 (internal, not published to players). The scoring
engine pushes rotated KoTH flags here via POST /internal/flag-update
with a shared-secret header (X-Koth-Secret).

The flag is written to /root/koth_flag.txt (mode 0600, owned by root).

Also serves GET /internal/flag (root-only) for the local flag service
that the SUID binary can access.
"""

import os
import hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)

FLAG_FILE = "/root/koth_flag.txt"
SECRET = os.environ.get("KOTH_FLAG_SECRET", "")

def write_flag(flag):
    """Write the flag to the flag file with root-only permissions."""
    # We're running as root (this service starts as root via entrypoint)
    with open(FLAG_FILE, "w") as f:
        f.write(flag.strip() + "\n")
    os.chmod(FLAG_FILE, 0o600)
    # Ensure root ownership
    try:
        os.chown(FLAG_FILE, 0, 0)
    except PermissionError:
        pass  # already root

@app.route("/internal/flag-update", methods=["POST"])
def flag_update():
    """Receive a rotated flag from the scoring engine."""
    secret = request.headers.get("X-Koth-Secret", "")
    if not SECRET or secret != SECRET:
        return jsonify({"error": "unauthorized"}), 403

    data = request.get_json(silent=True) or {}
    flag = str(data.get("flag", "")).strip()
    if not flag:
        return jsonify({"error": "flag required"}), 400

    write_flag(flag)
    print(f"[flag-service] flag updated: {flag[:8]}...", flush=True)
    return jsonify({"result": "flag updated"})

@app.route("/internal/flag", methods=["GET"])
def get_flag():
    """Return the current flag (root-only — this service runs as root)."""
    secret = request.headers.get("X-Koth-Secret", "")
    if not SECRET or secret != SECRET:
        return jsonify({"error": "unauthorized"}), 403

    if not os.path.exists(FLAG_FILE):
        return jsonify({"error": "no flag set"}), 404

    with open(FLAG_FILE, "r") as f:
        flag = f.read().strip()
    return jsonify({"flag": flag})

@app.route("/internal/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    # Write the initial flag if provided via env var
    initial = os.environ.get("KOTH_INITIAL_FLAG", "")
    if initial and not os.path.exists(FLAG_FILE):
        write_flag(initial)
        print(f"[flag-service] initial flag written: {initial[:8]}...", flush=True)

    app.run(host="0.0.0.0", port=8081, debug=False)