"""Generate public non-secret contracts from project root."""
from __future__ import annotations
import json
import tempfile
from pathlib import Path
from backend.app.config import AIConfig, AppSettings
from backend.app.main import create_app


def export():
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="pcapscanner-contracts-") as directory:
        app = create_app(AppSettings(data_dir=Path(directory), api_token=None))
        (root / "openapi.json").write_text(json.dumps(app.openapi(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    schema = AIConfig.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    (root / "ai-config.schema.json").write_text(json.dumps(schema, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("Generated non-secret OpenAPI 3.1 and AI JSON Schema 2020-12")


if __name__ == "__main__":
    export()
