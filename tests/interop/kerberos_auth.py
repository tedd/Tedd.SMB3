"""Independent Samba GENSEC Kerberos + SMB 3.1.1 signing/encryption interoperability.

Run inside the WSL test realm with KRB5_CONFIG, KRB5CCNAME and KRB5RCACHEDIR
pointing into its task workspace. No system Kerberos configuration is changed.
"""
import hashlib
import hmac
import os
import socket
import struct
import sys
import uuid

from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.cmac import CMAC
from samba import credentials, gensec
from samba.param import LoadParm

host, port, encrypted = sys.argv[1], int(sys.argv[2]), sys.argv[3] == "true"
user = sys.argv[4] if len(sys.argv) > 4 else "smbtest"
password = os.environ["TEDD_SMB_PASSWORD"]


def header(command, message, session=0, tree=0, flags=0):
    return struct.pack("<4sHHIHHIIQIIQ16s", b"\xfeSMB", 64, 1, 0, command, 1,
                       flags, 0, message, 0x1234, tree, session, bytes(16))


def context(kind, value):
    data = struct.pack("<HHI", kind, len(value), 0) + value
    return data + bytes(-len(data) % 8)


def exact(sock, count):
    result = b""
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise EOFError("SMB peer disconnected")
        result += part
    return result


def exchange(sock, data):
    sock.sendall(len(data).to_bytes(4, "big") + data)
    length = int.from_bytes(exact(sock, 4), "big")
    assert 52 <= length <= 131072
    return exact(sock, length)


def status(packet):
    return struct.unpack_from("<I", packet, 8)[0]


def token(packet):
    offset, count = struct.unpack_from("<HH", packet, 68)
    return packet[offset:offset+count]


lp = LoadParm()
lp.load(os.environ["SMB3_TEST_SAMBA_CONFIG"])
creds = credentials.Credentials()
creds.set_conf(lp)
creds.set_domain("SMB3TEST")
creds.set_realm("SMB3.TEST")
creds.set_username(user)
creds.set_password(password)
creds.set_kerberos_state(credentials.MUST_USE_KERBEROS)
security = gensec.Security.start_client({"lp_ctx": lp, "target_hostname": "smb3server.smb3.test"})
security.set_credentials(creds)
security.set_target_hostname("smb3server.smb3.test")
security.set_target_service("cifs")
security.want_feature(gensec.FEATURE_SESSION_KEY | gensec.FEATURE_SIGN)
security.start_mech_by_name("spnego")

with socket.create_connection((host, port), timeout=15) as sock:
    contexts = context(1, struct.pack("<HHH", 1, 32, 1) + os.urandom(32))
    contexts += context(2, struct.pack("<HH", 1, 2))
    contexts += context(8, struct.pack("<HH", 1, 1))
    contexts += context(3, struct.pack("<HHIH", 1, 0, 0, 1))
    body = struct.pack("<HHHHI16sIHHH", 36, 1, 3, 0, 64, uuid.uuid4().bytes, 104, 4, 0, 0x311) + bytes(2)
    negotiate = request = header(0, 0) + body + contexts
    transcript = hashlib.sha512(bytes(64) + request).digest()
    response = exchange(sock, request)
    assert status(response) == 0
    transcript = hashlib.sha512(transcript + response).digest()
    initial_offset, initial_count = struct.unpack_from("<HH", response, 120)
    done, output = security.update(response[initial_offset:initial_offset+initial_count])
    first_token = output
    session = 0
    message = 1
    for _ in range(8):
        body = struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 88, len(output), 0) + output
        request = header(1, message, session) + body
        transcript = hashlib.sha512(transcript + request).digest()
        response = exchange(sock, request)
        session = struct.unpack_from("<Q", response, 40)[0]
        if status(response) == 0:
            if not done:
                done, output = security.update(token(response))
            assert done
            break
        assert status(response) == 0xc0000016, hex(status(response))
        transcript = hashlib.sha512(transcript + response).digest()
        done, output = security.update(token(response))
        message += 1
    else:
        raise AssertionError("Kerberos exchange exceeded step limit")
    key = security.session_key()[:16]

    def derive(label):
        return hmac.new(key, b"\0\0\0\x01" + label + b"\0\0" + transcript + b"\0\0\0\x80", hashlib.sha256).digest()[:16]

    signing_key = derive(b"SMBSigningKey")

    def sign(packet):
        packet = packet[:48] + bytes(16) + packet[64:]
        mac = CMAC(algorithms.AES(signing_key))
        mac.update(packet)
        return packet[:48] + mac.finalize() + packet[64:]

    assert sign(response) == response, "Kerberos SESSION_SETUP signing key mismatch"
    compressed_responses = 0

    def decompress(packet):
        global compressed_responses
        if packet[:4] != b"\xfcSMB": return packet
        compressed_responses += 1
        expected, algorithm, flags, prefix = struct.unpack_from("<IHHI", packet, 4)
        assert algorithm == 1 and flags == 0 and expected + prefix <= 4194304
        source = 16 + prefix
        output = bytearray(packet[16:source])
        while source < len(packet):
            header_value, = struct.unpack_from("<H", packet, source)
            source += 2
            if header_value == 0: break
            end = source + (header_value & 0xfff) + 1
            start = len(output)
            if header_value & 0x8000:
                while source < end:
                    bits = packet[source]; source += 1
                    for bit in range(8):
                        if source == end: break
                        if bits & (1 << bit):
                            word, = struct.unpack_from("<H", packet, source); source += 2
                            position = len(output) - start
                            shift = 12
                            while (1 << (16 - shift)) < position: shift -= 1
                            length = (word & ((1 << shift) - 1)) + 3
                            distance = (word >> shift) + 1
                            for _ in range(length): output.append(output[-distance])
                        else:
                            output.append(packet[source]); source += 1
            else:
                output.extend(packet[source:end]); source = end
        assert len(output) == expected + prefix
        return bytes(output)

    def raw_compress(packet):
        if len(packet) < 1024: return packet
        result = struct.pack("<4sIHHI", b"\xfcSMB", len(packet), 1, 0, 0)
        for offset in range(0, len(packet), 4096):
            chunk = packet[offset:offset+4096]
            result += struct.pack("<H", 0x3000 | (len(chunk) - 1)) + chunk
        return result

    def authenticated(command, body, tree=0):
        global message
        message += 1
        packet = header(command, message, session, tree, flags=8 if not encrypted else 0) + body
        if not encrypted: packet = sign(packet)
        packet = raw_compress(packet)
        if encrypted:
            nonce = os.urandom(12)
            associated = nonce + bytes(4) + struct.pack("<IHHQ", len(packet), 0, 1, session)
            ciphertext = AESGCM(derive(b"SMBC2SCipherKey")).encrypt(nonce, packet, associated)
            response = exchange(sock, b"\xfdSMB" + ciphertext[-16:] + associated + ciphertext[:-16])
            assert response[:4] == b"\xfdSMB"
            response = AESGCM(derive(b"SMBS2CCipherKey")).decrypt(response[20:32], response[52:] + response[4:20], response[20:52])
        else:
            response = exchange(sock, packet)
        response = decompress(response)
        if not encrypted: assert sign(response) == response
        assert struct.unpack_from("<Q", response, 24)[0] == message
        return response

    assert status(authenticated(13, b"\x04\0\0\0")) == 0
    path = "\\\\smb3server.smb3.test\\files".encode("utf-16-le")
    response = authenticated(3, struct.pack("<HHHH", 9, 0, 72, len(path)) + path)
    if user != "smbtest":
        assert status(response) == 0xc0000022, "Unauthorized domain principal could connect to share"
        print(f"PASS Kerberos domain authentication with share authorization denial encrypted={encrypted}")
    else:
        assert status(response) == 0, hex(status(response))
        tree = struct.unpack_from("<I", response, 36)[0]
        name = ("kerberos-" + uuid.uuid4().hex).encode("utf-16-le")
        create = struct.pack("<HBBIQQIIIIIHHII", 57, 0, 0, 2, 0, 0, 0x13019f, 0x80, 7, 2, 0x1040, 120, len(name), 0, 0)
        response = authenticated(5, create + name, tree)
        assert status(response) == 0, hex(status(response))
        file_id = response[128:144]
        data = b"Independent Samba Kerberos file transfer" * 100
        write = struct.pack("<HHIQ16sIIHHI", 49, 112, len(data), 0, file_id, 0, 0, 0, 0, 0)
        assert status(authenticated(9, write + data, tree)) == 0
        read = struct.pack("<HBBIQ16sIIIHH", 49, 0, 0, len(data), 0, file_id, 0, 0, 0, 0, 0) + bytes(1)
        response = authenticated(8, read, tree)
        assert status(response) == 0
        offset, count = response[66], struct.unpack_from("<I", response, 68)[0]
        assert response[offset:offset+count] == data
        renamed = ("renamed-" + uuid.uuid4().hex).encode("utf-16-le")
        rename = bytes(8) + struct.pack("<QI", 0, len(renamed)) + renamed
        set_info = struct.pack("<HBBIHHI16s", 33, 1, 10, len(rename), 96, 0, 0, file_id)
        assert status(authenticated(17, set_info + rename, tree)) == 0
        assert status(authenticated(6, struct.pack("<HHI16s", 24, 1, 0, file_id), tree)) == 0
        assert compressed_responses > 0, "Server did not compress repetitive read data"
        print(f"PASS independent Samba Kerberos SMB 3.1.1 signing, encryption, LZNT1 and file round trip encrypted={encrypted}")
    assert status(authenticated(2, b"\x04\0\0\0")) == 0

# Replay the exact Kerberos authenticator on a new SMB connection. The acceptor's
# replay cache must reject it independently of SMB message IDs and preauth hashes.
with socket.create_connection((host, port), timeout=15) as replay:
    assert status(exchange(replay, negotiate)) == 0
    body = struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 88, len(first_token), 0) + first_token
    response = exchange(replay, header(1, 1) + body)
    assert status(response) == 0xc000006d, "Replayed Kerberos authenticator accepted"
print("PASS Kerberos authenticator replay rejected on a fresh SMB connection")
