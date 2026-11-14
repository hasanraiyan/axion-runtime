import json
import os
import sys
from pathlib import Path

# Add app parent directory to sys.path so it can run standalone
current_dir = Path(__file__).resolve().parent
app_dir = current_dir.parent.parent
if str(app_dir) not in sys.path:
    sys.path.insert(0, str(app_dir))

from app.main import app  # noqa: E402


def export_openapi(output_path: str = "openapi.json"):
    openapi_schema = app.openapi()
    target_path = Path(output_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    with open(target_path, "w", encoding="utf-8") as f:
        json.dump(openapi_schema, f, indent=2)

    print(f"OpenAPI schema successfully written to: {target_path.resolve()}")


if __name__ == "__main__":
    default_dest = str(app_dir / "openapi.json")
    dest = os.environ.get("EXPORT_PATH", default_dest)
    export_openapi(dest)
