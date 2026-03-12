#!/usr/bin/env python3
"""
RDP NLA Mock Server with full CredSSP pubKeyAuth support.
Validates credentials at the NTLM layer and completes the full CredSSP exchange
so freerdp's +auth-only returns proper exit codes.

Based on MS-NLMP and MS-CSSP specifications.
"""

import socket
import ssl
import struct
import hashlib
import hmac
import os
import sys
import logging
import base64

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('rdp_nla_mock')

# Valid credentials (username -> password)
VALID_CREDENTIALS = {
    'admin': 'admin',
    'root': 'root',
}

# RDP Protocol constants
PROTOCOL_HYBRID = 0x00000002  # NLA (CredSSP)

# NTLM constants
NTLMSSP_SIGNATURE = b'NTLMSSP\x00'
NTLM_NEGOTIATE = 1
NTLM_CHALLENGE = 2
NTLM_AUTHENTICATE = 3

# Negotiate flags
NTLMSSP_NEGOTIATE_UNICODE = 0x00000001
NTLMSSP_NEGOTIATE_NTLM = 0x00000200
NTLMSSP_NEGOTIATE_SEAL = 0x00000020
NTLMSSP_NEGOTIATE_SIGN = 0x00000010
NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
NTLMSSP_NEGOTIATE_TARGET_INFO = 0x00800000
NTLMSSP_NEGOTIATE_128 = 0x20000000
NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000


def md4(data):
    """MD4 hash - pure Python implementation."""
    def left_rotate(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xffffffff

    def F(x, y, z):
        return (x & y) | ((~x) & z)

    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def H(x, y, z):
        return x ^ y ^ z

    msg = bytearray(data)
    msg_len = len(data)
    msg.append(0x80)
    while (len(msg) % 64) != 56:
        msg.append(0x00)
    msg += struct.pack('<Q', msg_len * 8)

    A, B, C, D = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476

    for i in range(0, len(msg), 64):
        X = list(struct.unpack('<16I', msg[i:i+64]))
        AA, BB, CC, DD = A, B, C, D

        for j in range(16):
            s = [3, 7, 11, 19][j % 4]
            if j % 4 == 0:
                A = left_rotate((A + F(B, C, D) + X[j]) & 0xffffffff, s)
            elif j % 4 == 1:
                D = left_rotate((D + F(A, B, C) + X[j]) & 0xffffffff, s)
            elif j % 4 == 2:
                C = left_rotate((C + F(D, A, B) + X[j]) & 0xffffffff, s)
            else:
                B = left_rotate((B + F(C, D, A) + X[j]) & 0xffffffff, s)

        order2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        for j in range(16):
            k = order2[j]
            s = [3, 5, 9, 13][j % 4]
            if j % 4 == 0:
                A = left_rotate((A + G(B, C, D) + X[k] + 0x5a827999) & 0xffffffff, s)
            elif j % 4 == 1:
                D = left_rotate((D + G(A, B, C) + X[k] + 0x5a827999) & 0xffffffff, s)
            elif j % 4 == 2:
                C = left_rotate((C + G(D, A, B) + X[k] + 0x5a827999) & 0xffffffff, s)
            else:
                B = left_rotate((B + G(C, D, A) + X[k] + 0x5a827999) & 0xffffffff, s)

        order3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for j in range(16):
            k = order3[j]
            s = [3, 9, 11, 15][j % 4]
            if j % 4 == 0:
                A = left_rotate((A + H(B, C, D) + X[k] + 0x6ed9eba1) & 0xffffffff, s)
            elif j % 4 == 1:
                D = left_rotate((D + H(A, B, C) + X[k] + 0x6ed9eba1) & 0xffffffff, s)
            elif j % 4 == 2:
                C = left_rotate((C + H(D, A, B) + X[k] + 0x6ed9eba1) & 0xffffffff, s)
            else:
                B = left_rotate((B + H(C, D, A) + X[k] + 0x6ed9eba1) & 0xffffffff, s)

        A = (A + AA) & 0xffffffff
        B = (B + BB) & 0xffffffff
        C = (C + CC) & 0xffffffff
        D = (D + DD) & 0xffffffff

    return struct.pack('<4I', A, B, C, D)


def md5(data):
    """MD5 hash."""
    return hashlib.md5(data).digest()


def rc4_init(key):
    """Initialize RC4 state."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def rc4_crypt(state, data):
    """RC4 encrypt/decrypt with state."""
    S = state.copy()
    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(result), S


def ntowfv2(password, user, domain=''):
    """NTOWFv2 - NT One-Way Function v2."""
    nt_hash = md4(password.encode('utf-16-le'))
    return hmac.new(nt_hash, (user.upper() + domain).encode('utf-16-le'), 'md5').digest()


class NTLMContext:
    """NTLM security context for signing and sealing."""

    def __init__(self, session_base_key, is_server=True):
        self.session_base_key = session_base_key
        self.is_server = is_server
        self.seq_num = 0

        # Derive keys for Extended Session Security
        if is_server:
            sign_magic = b"session key to server-to-client signing key magic constant\x00"
            seal_magic = b"session key to server-to-client sealing key magic constant\x00"
        else:
            sign_magic = b"session key to client-to-server signing key magic constant\x00"
            seal_magic = b"session key to client-to-server sealing key magic constant\x00"

        self.sign_key = md5(session_base_key + sign_magic)
        self.seal_key = md5(session_base_key + seal_magic)
        self.rc4_state = rc4_init(self.seal_key)

    def seal(self, message):
        """Seal (encrypt) a message and compute NTLM signature."""
        # For NTLM with Extended Session Security:
        # 1. Compute HMAC-MD5 of SeqNum || Message
        # 2. Encrypt first 8 bytes of HMAC
        # 3. Build signature
        # 4. Encrypt message

        seq_bytes = struct.pack('<I', self.seq_num)
        self.seq_num += 1

        # HMAC-MD5(SigningKey, SeqNum || Message)
        mac = hmac.new(self.sign_key, seq_bytes + message, 'md5').digest()

        # Encrypt message with RC4 (using persistent state)
        encrypted, self.rc4_state = rc4_crypt(self.rc4_state, message)

        # Encrypt checksum with RC4 (using persistent state, continues from message)
        encrypted_mac, self.rc4_state = rc4_crypt(self.rc4_state, mac[:8])

        # Signature: Version (4 bytes) + EncryptedChecksum (8 bytes) + SeqNum (4 bytes)
        signature = struct.pack('<I', 1) + encrypted_mac + seq_bytes

        return encrypted, signature


class RDPNLAMock:
    def __init__(self, host='0.0.0.0', port=3389, cert_file='/certs/cert.pem', key_file='/certs/key.pem'):
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.server_challenge = None
        self.public_key = None

    def start(self):
        """Start the RDP NLA mock server."""
        # Load public key from certificate
        self.public_key = self.load_public_key()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(5)
        logger.info(f"RDP NLA Mock listening on {self.host}:{self.port}")

        while True:
            try:
                client, addr = sock.accept()
                logger.info(f"Connection from {addr}")
                self.handle_client(client, addr)
            except Exception as e:
                logger.error(f"Error accepting connection: {e}")

    def load_public_key(self):
        """Load SubjectPublicKeyInfo from certificate using OpenSSL."""
        import subprocess
        try:
            # Use OpenSSL to extract the public key in DER format
            result = subprocess.run(
                ['openssl', 'x509', '-in', self.cert_file, '-pubkey', '-noout'],
                capture_output=True
            )
            if result.returncode != 0:
                logger.error(f"OpenSSL error: {result.stderr.decode()}")
                return self._fallback_load_public_key()

            pubkey_pem = result.stdout.decode()

            # Convert PEM to DER
            lines = pubkey_pem.split('\n')
            b64 = ''.join(line for line in lines if not line.startswith('-----') and line.strip())
            pubkey_der = base64.b64decode(b64)

            logger.info(f"Loaded SubjectPublicKeyInfo: {len(pubkey_der)} bytes")
            return pubkey_der

        except Exception as e:
            logger.error(f"Error loading public key: {e}")
            return self._fallback_load_public_key()

    def _fallback_load_public_key(self):
        """Fallback: load entire certificate as public key."""
        try:
            with open(self.cert_file, 'rb') as f:
                cert_pem = f.read()
            lines = cert_pem.decode().split('\n')
            b64 = ''.join(line for line in lines if not line.startswith('-----'))
            return base64.b64decode(b64)
        except:
            return b'\x00' * 256

    def handle_client(self, client, addr):
        """Handle a single client connection."""
        ssl_client = None
        try:
            # Step 1: X.224 Connection Request
            data = client.recv(4096)
            if not data:
                return

            # Send X.224 CC with NLA support
            response = self.build_x224_cc(PROTOCOL_HYBRID)
            client.send(response)

            # Step 2: Upgrade to TLS
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.cert_file, self.key_file)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            ssl_client = context.wrap_socket(client, server_side=True)

            # Step 3: CredSSP/NLA exchange
            auth_result = self.handle_credssp(ssl_client)

            if auth_result:
                logger.info(f"Authentication SUCCESS for {addr}")
            else:
                logger.warning(f"Authentication FAILED for {addr}")

        except ssl.SSLError as e:
            logger.error(f"TLS error: {e}")
        except Exception as e:
            logger.error(f"Error handling client {addr}: {e}")
        finally:
            try:
                if ssl_client:
                    ssl_client.close()
                client.close()
            except:
                pass

    def build_x224_cc(self, protocol):
        """Build X.224 Connection Confirm with protocol selection."""
        neg_resp = struct.pack('<BBHI', 0x02, 0x00, 8, protocol)
        x224_cc = bytes([0x0e, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00]) + neg_resp
        total_len = 4 + len(x224_cc)
        tpkt = struct.pack('>BBH', 3, 0, total_len)
        return tpkt + x224_cc

    def handle_credssp(self, ssl_client):
        """Handle CredSSP (NLA) authentication with full pubKeyAuth."""
        try:
            # Receive NTLM Negotiate
            data = ssl_client.recv(4096)
            if not data:
                return False

            ntlm_negotiate = self.parse_tsrequest_token(data)
            if not ntlm_negotiate:
                logger.warning("Failed to parse NTLM Negotiate")
                return False

            # Send NTLM Challenge
            self.server_challenge = os.urandom(8)
            challenge_msg = self.build_ntlm_challenge(self.server_challenge)
            ssl_client.send(self.build_tsrequest_token(challenge_msg))

            # Receive NTLM Authenticate
            data = ssl_client.recv(8192)
            if not data:
                return False

            # Parse and validate credentials, get session key
            auth_result, ntlm_ctx = self.parse_and_validate_auth(data)

            if not auth_result:
                logger.warning("Credentials invalid")
                ssl_client.send(self.build_tsrequest_error())
                return False

            # Send pubKeyAuth (encrypted public key)
            logger.info("Credentials valid - sending pubKeyAuth")
            pub_key_auth = self.build_pub_key_auth(ntlm_ctx)
            ssl_client.send(pub_key_auth)

            # Receive client's credentials (TSCredentials)
            # For +auth-only, client will disconnect here after verifying pubKeyAuth
            try:
                data = ssl_client.recv(4096)
                if data:
                    logger.debug(f"Received credentials: {len(data)} bytes")
            except:
                pass

            return True

        except Exception as e:
            logger.error(f"CredSSP error: {e}")
            import traceback
            traceback.print_exc()
            return False

    def parse_tsrequest_token(self, data):
        """Parse TSRequest and extract negoToken."""
        idx = data.find(NTLMSSP_SIGNATURE)
        if idx < 0:
            return None
        return data[idx:]

    def build_ntlm_challenge(self, challenge):
        """Build NTLM Challenge message."""
        target_name = "WORKGROUP".encode('utf-16-le')
        target_info = self.build_target_info()

        target_name_offset = 56
        target_info_offset = target_name_offset + len(target_name)

        flags = (NTLMSSP_NEGOTIATE_UNICODE |
                 NTLMSSP_NEGOTIATE_NTLM |
                 NTLMSSP_NEGOTIATE_SIGN |
                 NTLMSSP_NEGOTIATE_SEAL |
                 NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
                 NTLMSSP_NEGOTIATE_TARGET_INFO |
                 NTLMSSP_NEGOTIATE_128 |
                 NTLMSSP_NEGOTIATE_KEY_EXCH)

        msg = NTLMSSP_SIGNATURE
        msg += struct.pack('<I', NTLM_CHALLENGE)
        msg += struct.pack('<HHI', len(target_name), len(target_name), target_name_offset)
        msg += struct.pack('<I', flags)
        msg += challenge
        msg += b'\x00' * 8  # Reserved
        msg += struct.pack('<HHI', len(target_info), len(target_info), target_info_offset)
        msg += b'\x00' * 8  # Version
        msg += target_name
        msg += target_info

        return msg

    def build_target_info(self):
        """Build NTLM Target Info AV_PAIRs."""
        info = b''
        domain = "WORKGROUP".encode('utf-16-le')
        info += struct.pack('<HH', 2, len(domain)) + domain
        computer = "RDP-TEST".encode('utf-16-le')
        info += struct.pack('<HH', 1, len(computer)) + computer
        info += struct.pack('<HH', 0, 0)  # MsvAvEOL
        return info

    def build_tsrequest_token(self, ntlm_msg):
        """Build TSRequest containing negoToken."""
        def encode_len(length):
            if length < 128:
                return bytes([length])
            elif length < 256:
                return bytes([0x81, length])
            else:
                return bytes([0x82]) + struct.pack('>H', length)

        # negoToken OCTET STRING
        token = bytes([0x04]) + encode_len(len(ntlm_msg)) + ntlm_msg
        # [0] negoToken
        tagged = bytes([0xa0]) + encode_len(len(token)) + token
        # SEQUENCE { negoToken }
        seq1 = bytes([0x30]) + encode_len(len(tagged)) + tagged
        # SEQUENCE OF
        seq2 = bytes([0x30]) + encode_len(len(seq1)) + seq1
        # [1] negoTokens
        nego_field = bytes([0xa1]) + encode_len(len(seq2)) + seq2
        # [0] version - use version 3 for simpler pubKeyAuth
        version = bytes([0xa0, 0x03, 0x02, 0x01, 0x03])  # version 3
        # TSRequest SEQUENCE
        body = version + nego_field
        return bytes([0x30]) + encode_len(len(body)) + body

    def parse_and_validate_auth(self, data):
        """Parse NTLM Authenticate and validate credentials. Returns (success, ntlm_context)."""
        try:
            idx = data.find(NTLMSSP_SIGNATURE)
            if idx < 0:
                return False, None

            ntlm_msg = data[idx:]
            if len(ntlm_msg) < 88:
                return False, None

            msg_type = struct.unpack('<I', ntlm_msg[8:12])[0]
            if msg_type != NTLM_AUTHENTICATE:
                return False, None

            def read_field(offset):
                length, _, field_offset = struct.unpack('<HHI', ntlm_msg[offset:offset+8])
                if length == 0:
                    return b''
                return ntlm_msg[field_offset:field_offset+length]

            nt_response = read_field(20)
            domain = read_field(28).decode('utf-16-le', errors='ignore')
            username = read_field(36).decode('utf-16-le', errors='ignore')
            encrypted_session_key = read_field(52)

            logger.info(f"Auth attempt: user={username} domain={domain}")

            # Find password
            password = None
            for u, p in VALID_CREDENTIALS.items():
                if u.lower() == username.lower():
                    password = p
                    break

            if not password:
                logger.warning(f"Unknown user: {username}")
                return False, None

            if len(nt_response) < 24:
                return False, None

            client_nt_proof = nt_response[:16]
            client_blob = nt_response[16:]

            # Compute expected response
            response_key = ntowfv2(password, username, domain)
            expected_nt_proof = hmac.new(response_key, self.server_challenge + client_blob, 'md5').digest()

            if client_nt_proof != expected_nt_proof:
                logger.warning(f"Password mismatch for {username}")
                return False, None

            logger.info(f"Password verified for {username}")

            # Compute session base key
            session_base_key = hmac.new(response_key, client_nt_proof, 'md5').digest()

            # If key exchange, decrypt the exported session key
            if encrypted_session_key:
                rc4_state = rc4_init(session_base_key)
                session_key, _ = rc4_crypt(rc4_state, encrypted_session_key)
            else:
                session_key = session_base_key

            # Create NTLM context for signing/sealing
            ntlm_ctx = NTLMContext(session_key, is_server=True)

            return True, ntlm_ctx

        except Exception as e:
            logger.error(f"Error parsing auth: {e}")
            import traceback
            traceback.print_exc()
            return False, None

    def build_pub_key_auth(self, ntlm_ctx):
        """Build TSRequest with pubKeyAuth containing sealed public key + 1."""
        # For CredSSP version < 5, server sends encrypted(public_key + 1)
        # The "+1" is a countermeasure against reflection attacks
        # Client will decrypt and subtract 1, then compare with TLS public key

        public_key = self.public_key

        # Increment public key by 1 (treat as big-endian integer)
        pk_bytes = bytearray(public_key)
        # Increment as little-endian integer (least significant byte first)
        carry = 1
        for i in range(len(pk_bytes)):
            val = pk_bytes[i] + carry
            pk_bytes[i] = val & 0xFF
            carry = val >> 8
            if carry == 0:
                break
        incremented_pk = bytes(pk_bytes)

        # Seal = encrypt + sign
        encrypted_pubkey, signature = ntlm_ctx.seal(incremented_pk)

        # pubKeyAuth format: Signature (16 bytes) || EncryptedData
        pub_key_auth = signature + encrypted_pubkey

        logger.info(f"pubKeyAuth: {len(pub_key_auth)} bytes (sig={len(signature)}, data={len(encrypted_pubkey)})")

        # Build TSRequest with pubKeyAuth [3]
        return self.build_tsrequest_pubkeyauth(pub_key_auth)

    def build_tsrequest_pubkeyauth(self, pub_key_auth):
        """Build TSRequest with pubKeyAuth field."""
        def encode_len(length):
            if length < 128:
                return bytes([length])
            elif length < 256:
                return bytes([0x81, length])
            else:
                return bytes([0x82]) + struct.pack('>H', length)

        # pubKeyAuth OCTET STRING
        pka_octet = bytes([0x04]) + encode_len(len(pub_key_auth)) + pub_key_auth
        # [3] pubKeyAuth
        pka_field = bytes([0xa3]) + encode_len(len(pka_octet)) + pka_octet
        # [0] version - use version 3 for simpler pubKeyAuth
        version = bytes([0xa0, 0x03, 0x02, 0x01, 0x03])  # version 3

        body = version + pka_field
        return bytes([0x30]) + encode_len(len(body)) + body

    def build_tsrequest_error(self):
        """Build TSRequest with error code."""
        # Use version 3 to match the challenge message
        version = bytes([0xa0, 0x03, 0x02, 0x01, 0x03])
        # errorCode [4] INTEGER - STATUS_LOGON_FAILURE = 0xC000006D
        error = bytes([0xa4, 0x06, 0x02, 0x04]) + struct.pack('>I', 0xC000006D)
        body = version + error
        return bytes([0x30, len(body)]) + body


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 3389
    server = RDPNLAMock(port=port)
    server.start()
