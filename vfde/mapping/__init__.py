import os

import yaml

_DIR = os.path.dirname(__file__)


def _load(name):
    with open(os.path.join(_DIR, name), encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def load_mitre():
    return _load("mitre.yaml")


def load_compliance():
    return _load("compliance.yaml")
