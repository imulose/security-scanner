"""Shared helpers used by all scanners."""

import os


def parse_exclude(raw: str) -> set:
    """Turn a comma/space separated string into a set of names to exclude."""
    if not raw:
        return set()
    parts = raw.replace(",", " ").split()
    return {p.strip() for p in parts if p.strip()}


def walk_files(path: str, exclude: set):
    """Yield every file path under `path` (file or directory), skipping names in `exclude`."""
    if os.path.isfile(path):
        yield path
        return

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in exclude]
        for filename in files:
            if filename in exclude:
                continue
            yield os.path.join(root, filename)
