import json
import re
from pathlib import Path

from packaging.version import InvalidVersion, Version

DATA = Path(__file__).resolve().parents[1] / "data" / "vulnerabilities.json"


def match_vulnerabilities(service: str, version: str) -> list[dict]:
    """Return advisory candidates, never proof of exploitability."""
    try:
        detected = Version(version)
    except InvalidVersion:
        return []
    matches = []
    for entry in json.loads(DATA.read_text()):
        if entry["product"].casefold() == service.casefold() and Version(
            entry["min"]
        ) <= detected < Version(entry["fixed"]):
            matches.append(entry)
    return matches


def parse_banner(banner: str) -> tuple[str, str]:
    match = re.search(r"(apache|nginx|openssh)[/ _-]([0-9]+(?:\.[0-9]+)+)", banner, re.IGNORECASE)
    return (match[1].lower(), match[2]) if match else (banner[:120], "")
