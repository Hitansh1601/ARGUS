"""Showcase phase 3: surgically remove ONLY the demo artifacts.

Usage: python scripts/showcase_cleanup.py <demo_dir>
Touches nothing else on the box: quarantines demo files, backs up + deletes
the single 'ARGUS Demo' HKCU Run value.
"""
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src import guard  # noqa: E402

DEMO_RUN_VALUE = "ARGUS Demo"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def main() -> int:
    demo = Path(sys.argv[1])
    print(guard.quarantine_file(str(demo / "demo-persist.vbe"), dry_run=False))
    print(guard.backup_persistence_value(
        "HKCU", RUN_KEY, DEMO_RUN_VALUE, str(demo / "demo-persist.vbe")))
    subprocess.run(
        ["reg", "delete", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
         "/v", DEMO_RUN_VALUE, "/f"], capture_output=True)
    print(f"Run value {DEMO_RUN_VALUE!r}: deleted (backup in feedback.db)")
    for name in ["doc1.locked", "doc2.locked", "doc3.locked", "doc4.locked",
                 "doc5.locked", "READ_ME.txt"]:
        print(guard.quarantine_file(str(demo / name), dry_run=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
