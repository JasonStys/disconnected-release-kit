"""Jason Stys: independent official SPDX schema checks and exact blob checksum relationships."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: test_official_spdx_schema — line 19
# variable: schema — line 21
# variable: data — line 27
# variable: record — line 31
# END CODE MAP

import json
from pathlib import Path

from conftest import NOW
from jsonschema import Draft7Validator, FormatChecker

from drkit.contracts import sha
from drkit.inventory import inventory


def test_official_spdx_schema() -> None:
    """Validate schema and real inventory against the immutable vendored SPDX upstream JSON schema."""
    schema = json.loads(
        (Path(__file__).resolve().parents[1] / "vendor/spdx-schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft7Validator.check_schema(schema)
    data = {
        "payload/wheels/example-1.0-py3-none-any.whl": b"synthetic wheel blob",
        "payload/service.py": b"# test",
    }
    record = json.loads(inventory(data, "demo-service", "1.0.0", NOW))
    Draft7Validator(schema, format_checker=FormatChecker()).validate(record)
    assert record["packages"][0]["checksums"][0]["checksumValue"] == sha(
        data["payload/wheels/example-1.0-py3-none-any.whl"]
    )
    assert record["packages"][0]["filesAnalyzed"] is False
    assert record["packages"][0]["licenseDeclared"] == "NOASSERTION"
    assert len(record["relationships"]) == 4
    assert inventory(data, "demo-service", "1.0.0", NOW) == inventory(
        dict(reversed(list(data.items()))), "demo-service", "1.0.0", NOW
    )
