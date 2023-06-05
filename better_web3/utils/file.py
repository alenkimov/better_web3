from pathlib import Path
import tomllib
import json


def load_json(filepath: Path) -> dict:
    if filepath.exists():
        with open(filepath, "r") as file:
            return json.load(file)
    else:
        raise FileNotFoundError(filepath)


def load_toml(filepath: Path) -> dict:
    if filepath.exists():
        with open(filepath, "rb") as file:
            return tomllib.load(file)
    else:
        raise FileNotFoundError(filepath)
