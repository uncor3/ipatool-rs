#!/usr/bin/env python3
"""Import the embedded Store profile from the pinned Go checkout (build-time only)."""
import base64
import pathlib
import re
import subprocess
import sys

REVISION = "d9c0247daea564d3ec7d04a9b015d0a29af66b04"
checkout = pathlib.Path(sys.argv[1])
revision = subprocess.check_output(
    ["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True
).strip()
if revision != REVISION:
    raise SystemExit(f"Expected Go revision {REVISION}, got {revision}")
source = subprocess.check_output(
    ["git", "-C", str(checkout), "show", f"{REVISION}:internal/store/profile/data_generated.go"],
    text=True,
)
destination = pathlib.Path(__file__).resolve().parents[1] / "src/store/profile/data"
destination.mkdir(parents=True, exist_ok=True)
for name in ("Metadata", "Pages", "Plugin"):
    match = re.search(
        rf"var generated{name} = artifact\{{\s*Name:\s*\"[^\"]+\",\s*"
        r"Size:\s*(\d+),\s*SHA256:\s*\"([0-9a-f]+)\",\s*Encoded:\s*`([^`]+)`",
        source,
    )
    if match is None:
        raise SystemExit(f"Missing {name} artifact")
    encoded = "".join(match[3].split())
    data = base64.b64decode(encoded, validate=True)
    (destination / f"{name.lower()}.zst").write_bytes(data)
    print(f"{name}: compressed={len(data)} decoded={match[1]} sha256={match[2]}")
