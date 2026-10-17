"""Independent smbprotocol filesystem and Impacket RPC interoperability checks."""
import io
import sys
import uuid

import smbclient
from smbprotocol.connection import Dialects

host, port, encrypted = sys.argv[1], int(sys.argv[2]), sys.argv[3] == "true"
session = smbclient.register_session(host, username="smbtest", password="testpass", port=port, encrypt=encrypted, require_signing=True)
assert session.connection.dialect == Dialects.SMB_3_1_1
folder = f"\\\\{host}\\files\\independent-{uuid.uuid4().hex}"
path = folder + "\\unicode-æøå-文件.bin"
data = bytes(range(256)) * 513
smbclient.mkdir(folder, port=port)
try:
    with smbclient.open_file(path, "wb", port=port) as stream:
        stream.write(data)
    with smbclient.open_file(path, "rb", port=port) as stream:
        assert stream.read() == data
    assert smbclient.listdir(folder, port=port) == ["unicode-æøå-文件.bin"]
    smbclient.rename(path, folder + "\\renamed.bin", port=port)
    path = folder + "\\renamed.bin"
    smbclient.remove(path, port=port)
    print(f"PASS independent smbprotocol SMB 3.1.1 encrypted={encrypted}: Unicode file round trip, listing, rename, delete")
finally:
    smbclient.rmdir(folder, port=port)
    smbclient.reset_connection_cache()
