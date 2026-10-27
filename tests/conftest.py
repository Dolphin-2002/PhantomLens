import os
import tempfile
from pathlib import Path

_database_dir = tempfile.TemporaryDirectory(prefix="spectermap-test-")
os.environ["SPECTERMAP_DATABASE_URL"] = "sqlite+aiosqlite:///" + str(
    Path(_database_dir.name) / "test.db"
)
