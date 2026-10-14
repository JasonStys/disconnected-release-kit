"""Jason Stys: synthetic trusted offline application, no external data, network access or commands."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: health — line 9
# END CODE MAP

import json


def health() -> dict[str, str]:
    """Return a fixed business-independent demonstration health response."""
    return {"status": "ready", "product": "demo-service", "author": "Jason Stys"}


if __name__ == "__main__":
    print(json.dumps(health(), sort_keys=True))
