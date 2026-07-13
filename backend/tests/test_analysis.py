from app.analyzers import extract_entities
from app.models import EntityType


def test_packetlens_entities_are_normalized_and_deduplicated() -> None:
    findings = {
        "engine": "packetlens",
        "result": {
            "top_talkers": [{"host": "10.0.0.8", "bytes": 400}],
            "dns_names": [{"name": "Example.COM.", "count": 3}],
            "http_hosts": [{"host": "example.com", "count": 2}],
            "tls_names": [],
            "observations": [],
        },
    }

    entities = extract_entities(findings)
    values = {(entity_type, value, source) for entity_type, value, source, _ in entities}

    assert (EntityType.IP, "10.0.0.8", "packetlens.talker") in values
    assert (EntityType.DOMAIN, "example.com", "packetlens.dns_names") in values
    assert (EntityType.DOMAIN, "example.com", "packetlens.http_hosts") in values


def test_crucible_entities_include_hashes_domains_and_mitre() -> None:
    sha256 = "a" * 64
    findings = {
        "engine": "crucible",
        "result": {
            "static": {
                "hashes": {"sha256": sha256},
                "strings": {
                    "flagged": {
                        "ipv4": ["callback 192.0.2.4"],
                        "url": ["https://updates.example.org/payload"],
                    }
                },
            },
            "mitre": [{"id": "T1059.004", "name": "Unix Shell"}],
        },
    }

    entities = extract_entities(findings)
    values = {(entity_type, value) for entity_type, value, _, _ in entities}

    assert (EntityType.HASH, sha256) in values
    assert (EntityType.IP, "192.0.2.4") in values
    assert (EntityType.DOMAIN, "updates.example.org") in values
    assert (EntityType.MITRE, "T1059.004") in values
