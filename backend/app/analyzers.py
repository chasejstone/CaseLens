from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .models import EntityType, EvidenceKind


DOMAIN_RE = re.compile(
    r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b"
)


def run_analysis(path: str, kind: EvidenceKind) -> dict[str, Any]:
    if kind == EvidenceKind.PCAP:
        return _analyze_pcap(path)
    return _analyze_file(path)


def _analyze_pcap(path: str) -> dict[str, Any]:
    from packetlens import analyze_pcap

    result = analyze_pcap(path, top=25)
    return {"engine": "packetlens", "result": result.to_dict()}


def _analyze_file(path: str) -> dict[str, Any]:
    import crucible
    from crucible.report import mitre, scorer
    from crucible.static import elf as elf_mod
    from crucible.static import entropy as entropy_mod
    from crucible.static import hashes, pe as pe_mod, strings as strings_mod, yara_scan
    from crucible.utils.filetype import sniff

    target = Path(path)
    file_type = sniff(target)
    static: dict[str, Any] = {"hashes": hashes.hash_file(target)}
    if file_type.kind == "pe":
        static["pe"] = pe_mod.parse(target)
    elif file_type.kind == "elf":
        static["elf"] = elf_mod.parse(target)

    binary = static.get("pe") or static.get("elf") or {}
    if binary.get("parsed"):
        static["section_summary"] = entropy_mod.summarize_sections(binary.get("sections", []))

    strings = strings_mod.analyze(target)
    static["strings"] = strings_mod.as_dict(strings)
    rules_dir = Path(crucible.__file__).resolve().parent.parent / "rules"
    static["yara"] = yara_scan.scan(target, rules_dir)
    findings: dict[str, Any] = {
        "meta": {
            "tool": "crucible",
            "version": getattr(crucible, "__version__", "unknown"),
            "path": target.name,
            "size": target.stat().st_size,
            "filetype": file_type.kind,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "static": static,
        "dynamic": {
            "ran": False,
            "reason": "dynamic execution is disabled in the shared CaseLens worker",
        },
    }
    score_result = scorer.score(findings)
    findings["scoring"] = {
        "score": score_result.score,
        "label": score_result.label,
        "indicators": score_result.indicators,
        "breakdown": score_result.breakdown,
    }
    findings["mitre"] = mitre.techniques_for(score_result.indicators)
    return {"engine": "crucible", "result": findings}


def extract_entities(findings: dict[str, Any]) -> list[tuple[EntityType, str, str, dict[str, Any]]]:
    engine = findings.get("engine")
    result = findings.get("result") or {}
    found: dict[tuple[EntityType, str, str], dict[str, Any]] = {}

    def add(entity_type: EntityType, value: str, source: str, context: dict[str, Any] | None = None):
        normalized = _normalize_entity(entity_type, value)
        if normalized:
            found[(entity_type, normalized, source)] = context or {}

    if engine == "packetlens":
        for row in result.get("top_talkers", []):
            add(EntityType.IP, str(row.get("host", "")), "packetlens.talker", row)
        for key in ("dns_names", "tls_names"):
            for row in result.get(key, []):
                add(EntityType.DOMAIN, str(row.get("name", "")), f"packetlens.{key}", row)
        for row in result.get("http_hosts", []):
            add(EntityType.DOMAIN, str(row.get("host", "")), "packetlens.http_hosts", row)
        for observation in result.get("observations", []):
            text = " ".join([str(observation.get("detail", "")), *map(str, observation.get("evidence", []))])
            for candidate in _ips_in_text(text):
                add(EntityType.IP, candidate, "packetlens.observation", {"title": observation.get("title")})
            for candidate in DOMAIN_RE.findall(text):
                add(
                    EntityType.DOMAIN,
                    candidate,
                    "packetlens.observation",
                    {"title": observation.get("title")},
                )

    if engine == "crucible":
        static = result.get("static") or {}
        for algorithm, value in (static.get("hashes") or {}).items():
            add(EntityType.HASH, str(value), f"crucible.{algorithm}", {"algorithm": algorithm})
        flagged = ((static.get("strings") or {}).get("flagged") or {})
        for value in flagged.get("ipv4", []):
            for candidate in _ips_in_text(value):
                add(EntityType.IP, candidate, "crucible.strings.ipv4")
        for value in flagged.get("url", []):
            host = urlparse(value).hostname
            if host:
                add(EntityType.DOMAIN, host, "crucible.strings.url")
        for technique in result.get("mitre", []):
            add(
                EntityType.MITRE,
                str(technique.get("id", "")),
                "crucible.mitre",
                {"name": technique.get("name", "")},
            )

    return [(entity_type, value, source, context) for (entity_type, value, source), context in found.items()]


def _normalize_entity(entity_type: EntityType, value: str) -> str | None:
    candidate = value.strip().strip(".")
    if not candidate:
        return None
    if entity_type == EntityType.IP:
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            return None
    if entity_type == EntityType.DOMAIN:
        lowered = candidate.lower()
        return lowered if DOMAIN_RE.fullmatch(lowered) else None
    if entity_type == EntityType.HASH:
        lowered = candidate.lower()
        return lowered if re.fullmatch(r"[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}", lowered) else None
    if entity_type == EntityType.MITRE:
        upper = candidate.upper()
        return upper if re.fullmatch(r"T\d{4}(?:\.\d{3})?", upper) else None
    return None


def _ips_in_text(text: str) -> set[str]:
    candidates = re.findall(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])", text)
    return {candidate for candidate in candidates if _normalize_entity(EntityType.IP, candidate)}
