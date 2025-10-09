import sys
from pathlib import Path
from email import policy
from email.parser import BytesParser
from email.generator import BytesGenerator
from io import BytesIO

def _strip_leading_mbox_from_line(data: bytes) -> bytes:
    """Remove mbox-style 'From ' delimiter line if present."""
    if data.startswith(b"From ") and b"\n" in data[:80]:
        first_nl = data.find(b"\n")
        if first_nl != -1:
            return data[first_nl + 1 :]
    return data

def convert_file(src_path: Path, dest_path: Path):
    """Convert one raw RFC-822 file into a normalized .eml file."""
    try:
        raw = src_path.read_bytes()
    except Exception as e:
        print(f"[SKIP] {src_path} - can't read ({e})")
        return

    # Skip binary files (likely attachments or non-text)
    if b"\0" in raw[:4096]:
        print(f"[SKIP] {src_path} - binary detected")
        return

    raw = _strip_leading_mbox_from_line(raw)

    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        buf = BytesIO()
        BytesGenerator(buf, policy=policy.SMTP).flatten(msg)
        dest_path.write_bytes(buf.getvalue())
        print(f"[OK] {src_path.name} → {dest_path.name}")
    except Exception as e:
        print(f"[FAIL] {src_path} → {e}")

def convert_folder(folder_name: str):
    src = Path(folder_name)
    if not src.exists() or not src.is_dir():
        print(f"Error: '{folder_name}' is not a valid folder.")
        return

    # Output folder name: EML_<original_folder_name>
    dest = src.parent / f"EML_{src.name}"
    dest.mkdir(parents=True, exist_ok=True)

    count = 0
    for file in src.rglob("*"):
        if not file.is_file():
            continue
        relative_path = file.relative_to(src)
        dest_file = (dest / relative_path).with_suffix(".eml")
        dest_file.parent.mkdir(parents=True, exist_ok=True)
        convert_file(file, dest_file)
        count += 1

    print(f"\n✅ Done! Converted {count} files → {dest}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python convert_to_eml_folder.py <folder_name>")
        sys.exit(1)

    convert_folder(sys.argv[1])
