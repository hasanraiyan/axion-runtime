"""
Drop obsolete MongoDB indexes left behind by earlier MOD-07 versions.

Run from apps/api:  python scripts/drop_legacy_indexes.py          (dry run: only reports)
                    python scripts/drop_legacy_indexes.py --apply  (drops them)
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pymongo import AsyncMongoClient  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.db.migrations import drop_legacy_indexes, legacy_indexes_present  # noqa: E402


async def main(apply: bool) -> int:
    client = AsyncMongoClient(settings.MONGODB_URL, serverSelectionTimeoutMS=settings.MONGODB_SERVER_SELECTION_TIMEOUT_MS)
    try:
        database = client[settings.MONGODB_DB_NAME]
        present = await legacy_indexes_present(database)
        if not present:
            print("No obsolete indexes found.")
            return 0
        if not apply:
            print(f"Obsolete indexes found: {present}. Re-run with --apply to drop them.")
            return 1
        print(f"Dropped: {await drop_legacy_indexes(database)}")
        return 0
    finally:
        await client.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main("--apply" in sys.argv[1:])))
