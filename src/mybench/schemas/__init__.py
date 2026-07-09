"""Packaged JSON Schemas — the machine-checked whitelists for every artifact."""

import json
from functools import lru_cache
from importlib import resources

import jsonschema


@lru_cache(maxsize=None)
def load_validator(name: str) -> jsonschema.Draft202012Validator:
    schema = json.loads(resources.files("mybench.schemas").joinpath(name).read_text())
    return jsonschema.Draft202012Validator(schema)
