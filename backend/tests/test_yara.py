from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import sys
import time
from pathlib import Path

import pytest
from pydantic import ValidationError

from backend.app.config import AppSettings, _env_overlay
from backend.app.llm.providers import _safe_context
from backend.app.pipeline import _Accumulator, _build_bundle, _get_limits, _run_yara, _stage
from backend.app.yara import YaraRulesError, snapshot_ruleset
from backend.app.zeek import bounded_directory_size

HASH = "a" * 64
RULE_TEXT = 'rule TestRule { strings: $a = "test-content" condition: $a }\n'


def test_snapshot_ruleset_hashes_copies_and_rejects_include(tmp_path: Path) -> None:
    source = tmp_path / "rules"
    source.mkdir()
    (source / "safe.yar").write_text(RULE_TEXT, encoding="utf-8")
    output = tmp_path / "snapshot"
    snapshot = snapshot_ruleset(source, output, max_files=4, max_bytes=4096)
    assert snapshot.rule_count == 1
    assert snapshot.rule_names == {"TestRule"}
    assert snapshot.sha256 == hashlib.sha256(b"safe.yar\0" + RULE_TEXT.encode()).hexdigest()
    copied = snapshot.files[0]
    assert copied.read_text(encoding="utf-8") == RULE_TEXT
    if os.name == "posix":
        assert stat.S_IMODE(copied.stat().st_mode) == 0o400

    (source / "unsafe.yar").write_text('include "outside.yar"\n' + RULE_TEXT, encoding="utf-8")
    with pytest.raises(YaraRulesError, match="rules_include_forbidden"):
        snapshot_ruleset(source, tmp_path / "snapshot-2", max_files=4, max_bytes=4096)


def test_snapshot_ruleset_enforces_file_and_byte_caps(tmp_path: Path) -> None:
    source = tmp_path / "rules"
    source.mkdir()
    (source / "one.yar").write_text(RULE_TEXT, encoding="utf-8")
    (source / "two.yar").write_text(RULE_TEXT.replace("TestRule", "OtherRule"), encoding="utf-8")
    with pytest.raises(YaraRulesError, match="rules_file_limit_exceeded"):
        snapshot_ruleset(source, tmp_path / "snapshot", max_files=1, max_bytes=4096)
    with pytest.raises(YaraRulesError, match="rules_byte_limit_exceeded"):
        snapshot_ruleset(source, tmp_path / "snapshot-2", max_files=4, max_bytes=100)


def test_recursive_output_budget_counts_nested_objects_and_rejects_symlinks(tmp_path: Path) -> None:
    root = tmp_path / "run"
    nested = root / "objects" / "nested"
    nested.mkdir(parents=True)
    (nested / "object.bin").write_bytes(b"12345678901")
    assert bounded_directory_size(root, 10) == (11, True)
    assert bounded_directory_size(root, 11) == (11, False)
    link = root / "objects" / "outside"
    try:
        link.symlink_to(nested / "object.bin")
    except (NotImplementedError, OSError):
        return
    assert bounded_directory_size(root, 100) == (101, True)


def test_yara_configuration_is_default_off_and_caps_are_validated() -> None:
    assert AppSettings().yara_enabled is False
    config = AppSettings.model_validate(
        _env_overlay(
            {
                "PCAP_YARA_ENABLED": "1",
                "PCAP_YARA_RULES_DIR": "/rules",
                "PCAP_YARA_MAX_OBJECTS": "12",
                "PCAP_YARA_MAX_TOTAL_BYTES": "8388608",
                "PCAP_YARA_MAX_OBJECT_BYTES": "4194304",
                "PCAP_YARA_TIMEOUT_SECONDS": "15",
            }
        )
    )
    assert config.yara_enabled is True
    assert config.yara_rules_dir == Path("/rules")
    assert config.yara_max_objects == 12
    assert config.yara_max_total_bytes == 8 * 1024 * 1024
    assert config.yara_timeout_seconds == 15
    with pytest.raises(ValidationError):
        AppSettings(yara_max_object_bytes=8 * 1024 * 1024, yara_max_total_bytes=4 * 1024 * 1024)
    with pytest.raises(ValidationError):
        AppSettings(
            yara_max_rules_bytes=64 * 1024 * 1024,
            yara_max_total_bytes=192 * 1024 * 1024,
            yara_max_output_bytes=16 * 1024 * 1024,
        )


def test_yara_match_is_evidence_with_no_raw_payload_or_external_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    capture = tmp_path / "safe.pcap"
    capture.write_bytes(b"synthetic capture")
    rules = tmp_path / "operator-rules"
    rules.mkdir()
    (rules / "safe.yar").write_text(RULE_TEXT, encoding="utf-8")
    argv_file = tmp_path / "yara-argv.json"

    fake_tshark = tmp_path / "fake-tshark"
    fake_tshark.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib, sys\n"
        "spec = sys.argv[sys.argv.index('--export-objects') + 1]\n"
        "out = pathlib.Path(spec.split(',', 1)[1])\n"
        "(out / 'exported.dat').write_bytes(b'test-content-private-payload')\n",
        encoding="utf-8",
    )
    fake_yara = tmp_path / "fake-yara"
    fake_yara.write_text(
        "#!/usr/bin/env python3\n"
        "import json, pathlib, sys\n"
        f"pathlib.Path({str(argv_file)!r}).write_text(json.dumps(sys.argv[1:]), encoding='utf-8')\n"
        "scan_list = pathlib.Path(sys.argv[sys.argv.index('--scan-list') + 1])\n"
        "target = pathlib.Path(scan_list.read_text().splitlines()[0])\n"
        "if b'test-content' in target.read_bytes(): print('TestRule', target)\n",
        encoding="utf-8",
    )
    fake_tshark.chmod(fake_tshark.stat().st_mode | stat.S_IXUSR)
    fake_yara.chmod(fake_yara.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setattr(
        "backend.app.pipeline.shutil.which",
        lambda name: str(fake_tshark) if name == "tshark" else (str(fake_yara) if name == "yara" else None),
    )
    settings = AppSettings(
        yara_enabled=True,
        yara_rules_dir=rules,
        yara_max_total_bytes=2 * 1024 * 1024,
        yara_max_object_bytes=1024 * 1024,
        parser_memory_mb=512,
    )
    limits = _get_limits(settings)
    stage, records = _run_yara(capture, limits=limits, deadline=time.monotonic() + 10, is_cancelled=lambda: False)
    assert stage.state == "completed", stage.detail
    assert len(records) == 1
    assert records[0].rule_id == "TestRule"
    assert records[0].object_sha256 == hashlib.sha256(b"test-content-private-payload").hexdigest()
    assert records[0].ruleset_sha256 == snapshot_ruleset(
        rules, tmp_path / "rules-copy", max_files=64, max_bytes=16 * 1024 * 1024
    ).sha256
    assert "--scan-list" in json.loads(argv_file.read_text(encoding="utf-8"))

    bundle = _build_bundle(
        _Accumulator(packet_limit=100, flow_limit=100),
        capture_sha256=HASH,
        parser_state="completed",
        parser_detail="bounded test",
        zeek_stage=_stage("zeek", "skipped", "off"),
        yara_stage=stage,
        yara_records=records,
    )
    evidence = next(item for item in bundle.evidence if item.kind == "yara")
    assert evidence.evidence_id == "EV-000001"
    assert evidence.attributes["artifact_sha256"] == records[0].object_sha256
    finding = next(item for item in bundle.findings if item.detector == "yara_rule_match")
    assert finding.evidence_ids == [evidence.evidence_id]
    assert "test-content-private-payload" not in evidence.model_dump_json()
    safe = json.dumps(_safe_context(bundle, b"test-salt"), sort_keys=True)
    assert "test-content-private-payload" not in safe
    assert str(tmp_path) not in safe
    assert records[0].object_sha256 not in safe
    assert records[0].ruleset_sha256 not in safe
    assert "TestRule" not in safe
    assert '"match_count": 1' in safe
    assert "yara" in safe


def test_yara_disabled_never_executes_or_reads_rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"synthetic")
    monkeypatch.setattr("backend.app.pipeline.shutil.which", lambda _name: None)
    limits = _get_limits(AppSettings(yara_enabled=False))
    stage, records = _run_yara(capture, limits=limits, deadline=time.monotonic() + 2, is_cancelled=lambda: False)
    assert stage.state == "skipped"
    assert records == []


@pytest.mark.skipif(shutil.which("yara") is None, reason="YARA CLI is not installed in this test environment")
def test_real_yara_cli_scan_list_and_no_match_exit_semantics(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"synthetic capture")
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "sample.yar").write_text(
        'rule ActualCliMatch { strings: $a = "actual-yara-cli-test" condition: $a }\n',
        encoding="utf-8",
    )
    fake_tshark = tmp_path / "fake-tshark"
    fake_tshark.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib, sys\n"
        "out = pathlib.Path(sys.argv[sys.argv.index('--export-objects') + 1].split(',', 1)[1])\n"
        "(out / 'matching.bin').write_bytes(b'actual-yara-cli-test')\n"
        "(out / 'nonmatching.bin').write_bytes(b'benign-synthetic-object')\n",
        encoding="utf-8",
    )
    fake_tshark.chmod(fake_tshark.stat().st_mode | stat.S_IXUSR)
    real_which = shutil.which

    def which(name: str) -> str | None:
        return str(fake_tshark) if name == "tshark" else real_which(name)

    monkeypatch.setattr("backend.app.pipeline.shutil.which", which)
    limits = _get_limits(
        AppSettings(
            yara_enabled=True,
            yara_rules_dir=rules,
            yara_max_total_bytes=2 * 1024 * 1024,
            yara_max_object_bytes=1024 * 1024,
        )
    )
    stage, records = _run_yara(
        capture,
        limits=limits,
        deadline=time.monotonic() + 10,
        is_cancelled=lambda: False,
    )
    assert stage.state == "completed", stage.detail
    assert len(records) == 1
    assert records[0].rule_id == "ActualCliMatch"
    assert records[0].object_size_bytes == len(b"actual-yara-cli-test")
