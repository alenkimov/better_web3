from pathlib import Path
import tomllib
import json


def load_json(filepath: Path | str) -> dict:
    with open(filepath, "r") as file:
        return json.load(file)


def load_toml(filepath: Path | str) -> dict:
    with open(filepath, "rb") as file:
        return tomllib.load(file)
