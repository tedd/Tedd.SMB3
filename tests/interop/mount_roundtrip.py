"""Exercise a real mounted filesystem; argument must be a disposable test mount."""
import hashlib
import os
from pathlib import Path
import sys
import uuid

mount = Path(sys.argv[1])
folder = mount / ("native-" + uuid.uuid4().hex)
data = bytes(range(256)) * 1025 + b"SMB3 acceptance"
folder.mkdir()
original = folder / "unicode-æøå-文件.bin"
renamed = folder / "renamed.bin"
try:
    with original.open("wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    assert original.read_bytes() == data
    assert original.stat().st_size == len(data)
    assert original.name in [p.name for p in folder.iterdir()]
    original.rename(renamed)
    with renamed.open("r+b") as stream:
        stream.truncate(32771)
        stream.seek(65536)
        stream.write(b"offset")
        stream.flush()
        os.fsync(stream.fileno())
    expected = data[:32771] + bytes(65536 - 32771) + b"offset"
    assert renamed.read_bytes() == expected
    os.utime(renamed, (1700000000, 1700000000))
    assert abs(renamed.stat().st_mtime - 1700000000) <= 2
    print(f"PASS native mount {mount}: Unicode, listing, create/read/write, SHA256={hashlib.sha256(expected).hexdigest()}, rename, truncate, sparse offset, flush, timestamps, delete")
finally:
    for path in (original, renamed):
        if path.exists():
            path.unlink()
    folder.rmdir()
