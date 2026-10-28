#!/usr/bin/env python3
"""AM-03 internal diagnostics service. Reachable only from the
Junction 7 internal Docker network (no host port publish) — this is
the "internal interface" leg of the exploit chain, hit by pivoting from
a shell on the public junction7 host.

Substitution note (see ../../README.md): the original design candidate
for this slot was a real vulnerable third-party WAR (Struts2 showcase),
but bundling/verifying a genuine third-party binary isn't practical in
this build environment, so this host instead ships a small, original,
100%-real vulnerable service: a "network diagnostics" endpoint that
shells out to `ping` with unsanitized input. Real OS command injection,
fully working, matches the "internal tool RCE" vuln class from
AM_SOURCING.md just as directly as the WAR-based candidate did.
"""
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/diag")
def diag():
    host = request.args.get("host", "127.0.0.1")
    # Intentionally vulnerable: unsanitized shell interpolation.
    try:
        out = subprocess.check_output(
            f"ping -c 1 -W 2 {host}", shell=True, stderr=subprocess.STDOUT
        )
    except subprocess.CalledProcessError as e:
        out = e.output
    return out, 200, {"Content-Type": "text/plain"}


@app.route("/")
def index():
    return (
        "JUNCTION 7 — INTERNAL DIAGNOSTICS\n"
        "GET /diag?host=<target> — reachability check\n",
        200,
        {"Content-Type": "text/plain"},
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
