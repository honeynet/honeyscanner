import json
from pathlib import Path
from typing import Any

from honeyscanner.report_generator import ReportGenerator


class MockHoneypot:
    def __init__(self) -> None:
        self.name = "cowrie"
        self.version = "2.5.0"
        self.ip = "127.0.0.1"
        self.ports = [22, 2222]


def test_generate_report_dict() -> None:
    honeypot: Any = MockHoneypot()
    generator = ReportGenerator(honeypot)
    recs = ["Update SSH credentials", "Disable root login"]
    passive = "Cowrie honeypot detected on port 22."
    active = ("DoS attack completed.", 0, 0)

    report = generator.generate(recs, passive, active)

    assert "metadata" in report
    assert "results" in report
    assert "recommendations" in report
    assert report["metadata"]["honeypot"]["name"] == "cowrie"
    assert report["metadata"]["honeypot"]["ip"] == "127.0.0.1"
    assert report["recommendations"] == recs


def test_save_json_report(tmp_path: Path) -> None:
    honeypot: Any = MockHoneypot()
    generator = ReportGenerator(honeypot)
    recs = ["Recommendation 1: Use UTF-8 — ✓"]
    passive = "Passive scan ok"
    active = ("Active scan ok", 0, 0)

    report = generator.generate(recs, passive, active)
    original_filename = report["metadata"]["filename"]
    assert original_filename.endswith(".txt")

    json_path = generator.save_json(report, output_dir=tmp_path)

    assert json_path.exists()
    assert json_path.suffix == ".json"

    # Verify caller's dict was not mutated
    assert report["metadata"]["filename"] == original_filename

    with open(json_path, "r", encoding="utf-8") as f:
        loaded_report = json.load(f)

    # Verify saved metadata filename matches JSON file name
    assert loaded_report["metadata"]["filename"] == json_path.name
    assert loaded_report["metadata"]["filename"].endswith(".json")
    assert loaded_report["metadata"]["honeypot"]["name"] == "cowrie"
    assert loaded_report["results"]["passive"] == "Passive scan ok"
    assert loaded_report["recommendations"] == recs
