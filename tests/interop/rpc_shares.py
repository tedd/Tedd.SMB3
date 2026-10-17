import sys
from impacket.smbconnection import SMBConnection
from impacket.smb3structs import SMB2_DIALECT_311

host, port = sys.argv[1], int(sys.argv[2])
client = SMBConnection(host, host, sess_port=port, preferredDialect=SMB2_DIALECT_311)
try:
    client.login("smbtest", "testpass", "WORKGROUP")
    names = [str(row["shi1_netname"]).rstrip("\0") for row in client.listShares()]
    assert sorted(names) == ["IPC$", "files"], names
    print("PASS independent Impacket srvsvc share enumeration:", names)
finally:
    client.logoff()
    client.close()
