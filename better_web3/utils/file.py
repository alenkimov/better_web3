import json
from pathlib import Path


def load_lines(filepath: Path | str) -> list[str]:
    with open(filepath, "r") as file:
        return [line.strip() for line in file.readlines() if line != "\n"]


def load_json(filepath: Path | str) -> dict:
    with open(filepath, "r") as file:
        return json.load(file)
