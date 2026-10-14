"""Jason Stys: deterministic SPDX 2.3 blob/file inventory; no invented dependency or license claims."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: inventory — line 29
# parameter: created — line 30
# parameter: files — line 30
# parameter: product — line 30
# parameter: version — line 30
# variable: data — line 33
# variable: identity — line 33
# variable: name — line 33
# variable: records — line 34
# variable: packages — line 35
# variable: relationships — line 36
# variable: data — line 37
# variable: index — line 37
# variable: name — line 37
# variable: identifier — line 38
# variable: package_id — line 56
# END CODE MAP

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from drkit.contracts import canonical, sha


def inventory(
    files: dict[str, bytes], product: str, version: str, created: int
) -> bytes:
    """Describe exact carried files and wheel blobs, not inferred transitive dependencies or licenses."""
    identity = sha(canonical({name: sha(data) for name, data in sorted(files.items())}))
    records: list[dict[str, Any]] = []
    packages: list[dict[str, Any]] = []
    relationships: list[dict[str, str]] = []
    for index, (name, data) in enumerate(sorted(files.items())):
        identifier = f"SPDXRef-File-{index}"
        records.append(
            dict(
                SPDXID=identifier,
                fileName="./" + name,
                checksums=[dict(algorithm="SHA256", checksumValue=sha(data))],
                licenseConcluded="NOASSERTION",
                copyrightText="NOASSERTION",
            )
        )
        relationships.append(
            dict(
                spdxElementId="SPDXRef-DOCUMENT",
                relatedSpdxElement=identifier,
                relationshipType="DESCRIBES",
            )
        )
        if name.endswith(".whl"):
            package_id = f"SPDXRef-Package-{index}"
            packages.append(
                dict(
                    SPDXID=package_id,
                    name=name.rsplit("/", 1)[-1],
                    downloadLocation="NOASSERTION",
                    filesAnalyzed=False,
                    checksums=[dict(algorithm="SHA256", checksumValue=sha(data))],
                    licenseConcluded="NOASSERTION",
                    licenseDeclared="NOASSERTION",
                )
            )
            relationships.append(
                dict(
                    spdxElementId=package_id,
                    relatedSpdxElement=identifier,
                    relationshipType="CONTAINS",
                )
            )
            relationships.append(
                dict(
                    spdxElementId="SPDXRef-DOCUMENT",
                    relatedSpdxElement=package_id,
                    relationshipType="DESCRIBES",
                )
            )
    return canonical(
        dict(
            spdxVersion="SPDX-2.3",
            dataLicense="CC0-1.0",
            SPDXID="SPDXRef-DOCUMENT",
            name=f"{product}-{version}-inventory",
            documentNamespace=f"https://github.com/JasonStys/disconnected-release-kit/spdx/{product}/{version}/{created}/{identity}",
            creationInfo=dict(
                created=datetime.fromtimestamp(created, UTC).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                creators=["Person: Jason Stys", "Tool: disconnected-release-kit-1.0.0"],
            ),
            files=records,
            packages=packages,
            relationships=relationships,
        )
    )
