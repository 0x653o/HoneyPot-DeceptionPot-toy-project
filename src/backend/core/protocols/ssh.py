"""
SSH Protocol Handler — Mimics OpenSSH 8.9p1

Sends a realistic SSH banner, performs a simulated key exchange,
captures authentication credentials (username/password), and logs
client version strings and key exchange parameters.

All responses are pure string I/O — no real SSH daemon.
"""

import asyncio
import os
import struct
import hashlib
from typing import Optional

from .base import BaseProtocolHandler
from ..config import ProtocolConfig
from ..logger import HoneypotLogger


class SSHHandler(BaseProtocolHandler):
    """Fake SSH server mimicking OpenSSH 8.9p1 Ubuntu."""

    PROTOCOL_NAME = "ssh"

    # Bait: OpenSSH 7.4 banner — known-vulnerable to CVE-2018-15473
    # (user enumeration). Attracts automated scanners.
    BANNER = b"SSH-2.0-OpenSSH_7.4\r\n"

    # Key exchange algorithms (matches real OpenSSH 8.9)
    KEX_ALGORITHMS = (
        "curve25519-sha256,curve25519-sha256@libssh.org,"
        "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
        "diffie-hellman-group-exchange-sha256,"
        "diffie-hellman-group14-sha256,"
        "diffie-hellman-group16-sha512,"
        "diffie-hellman-group18-sha512"
    )

    HOST_KEY_ALGORITHMS = (
        "ssh-ed25519-cert-v01@openssh.com,"
        "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
        "ecdsa-sha2-nistp384-cert-v01@openssh.com,"
        "ecdsa-sha2-nistp521-cert-v01@openssh.com,"
        "sk-ssh-ed25519-cert-v01@openssh.com,"
        "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,"
        "rsa-sha2-512-cert-v01@openssh.com,"
        "rsa-sha2-256-cert-v01@openssh.com,"
        "ssh-ed25519,ecdsa-sha2-nistp256,"
        "ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,"
        "sk-ssh-ed25519@openssh.com,"
        "sk-ecdsa-sha2-nistp256@openssh.com,"
        "rsa-sha2-512,rsa-sha2-256"
    )

    ENCRYPTION_ALGORITHMS = (
        "chacha20-poly1305@openssh.com,"
        "aes128-ctr,aes192-ctr,aes256-ctr,"
        "aes128-gcm@openssh.com,aes256-gcm@openssh.com"
    )

    MAC_ALGORITHMS = (
        "umac-64-etm@openssh.com,umac-128-etm@openssh.com,"
        "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,"
        "hmac-sha1-etm@openssh.com,"
        "umac-64@openssh.com,umac-128@openssh.com,"
        "hmac-sha2-256,hmac-sha2-512,hmac-sha1"
    )

    COMPRESSION = "none,zlib@openssh.com"

    def __init__(self, config: ProtocolConfig, logger: HoneypotLogger):
        super().__init__(config, logger)
        self._max_auth_attempts = config.max_auth_attempts
        if config.banner:
            self._banner = config.banner.encode() + b"\r\n"
        else:
            self._banner = self.BANNER

    def _build_kexinit_payload(self) -> bytes:
        """
        Build a realistic SSH_MSG_KEXINIT packet payload.
        This mimics the binary format that real SSH clients expect.
        """
        # SSH_MSG_KEXINIT = 20
        msg_type = bytes([20])
        # 16 bytes random cookie
        cookie = os.urandom(16)

        def _encode_namelist(s: str) -> bytes:
            encoded = s.encode("utf-8")
            return struct.pack(">I", len(encoded)) + encoded

        payload = msg_type + cookie
        # kex_algorithms
        payload += _encode_namelist(self.KEX_ALGORITHMS)
        # server_host_key_algorithms
        payload += _encode_namelist(self.HOST_KEY_ALGORITHMS)
        # encryption_algorithms_client_to_server
        payload += _encode_namelist(self.ENCRYPTION_ALGORITHMS)
        # encryption_algorithms_server_to_client
        payload += _encode_namelist(self.ENCRYPTION_ALGORITHMS)
        # mac_algorithms_client_to_server
        payload += _encode_namelist(self.MAC_ALGORITHMS)
        # mac_algorithms_server_to_client
        payload += _encode_namelist(self.MAC_ALGORITHMS)
        # compression_algorithms_client_to_server
        payload += _encode_namelist(self.COMPRESSION)
        # compression_algorithms_server_to_client
        payload += _encode_namelist(self.COMPRESSION)
        # languages_client_to_server
        payload += _encode_namelist("")
        # languages_server_to_client
        payload += _encode_namelist("")
        # first_kex_packet_follows
        payload += bytes([0])
        # reserved
        payload += struct.pack(">I", 0)

        return payload

    def _build_ssh_packet(self, payload: bytes) -> bytes:
        """Wrap payload in SSH binary packet format."""
        # Minimum padding is 4 bytes, block size is 8
        block_size = 8
        # packet_length = padding_length(1) + payload_length + padding
        padding_length = block_size - ((1 + len(payload)) % block_size)
        if padding_length < 4:
            padding_length += block_size

        packet_length = 1 + len(payload) + padding_length
        padding = os.urandom(padding_length)

        packet = struct.pack(">I", packet_length)
        packet += bytes([padding_length])
        packet += payload
        packet += padding

        return packet

    async def handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        session_id: Optional[str] = None,
    ):
        """Handle an SSH connection."""
        ip, port = self._get_peer_info(writer)
        conn_id = self._logger.log_connection("ssh", ip, port, session_id)

        try:
            # Step 1: Send server banner
            await self._safe_write(writer, self._banner)

            # Step 2: Read client banner
            client_banner = await self._safe_readline(reader, timeout=15.0)
            if not client_banner:
                return

            client_version = client_banner.decode("utf-8", errors="replace").strip()
            self._logger.log_event(conn_id, "client_version", client_version)

            # Step 3: Send SSH_MSG_KEXINIT
            kexinit_payload = self._build_kexinit_payload()
            kexinit_packet = self._build_ssh_packet(kexinit_payload)
            await self._safe_write(writer, kexinit_packet)

            # Step 4: Read client's KEXINIT (we just capture it, don't parse)
            client_kex = await self._safe_read(reader, max_bytes=8192, timeout=15.0)
            if client_kex:
                self._logger.log_event(
                    conn_id, "client_kexinit",
                    f"KEX data ({len(client_kex)} bytes)"
                )

            # Step 5: Simulate auth interaction
            # After KEX, real SSH transitions to encrypted channel.
            # Since we can't do real crypto, we'll handle the common case
            # where scanners/bots just send credentials in a simplified way.
            # Many attack tools send credentials after banner exchange.
            
            for attempt in range(self._max_auth_attempts):
                # Read any data the client sends (auth attempts)
                auth_data = await self._safe_read(
                    reader, max_bytes=4096, timeout=30.0
                )
                if not auth_data:
                    break

                # Try to extract credentials from the raw data
                self._extract_and_log_credentials(conn_id, ip, auth_data)

                # Send "Permission denied" equivalent
                # SSH_MSG_USERAUTH_FAILURE = 51
                failure_msg = self._build_auth_failure()
                await self._safe_write(writer, failure_msg)

            # Final disconnect
            # SSH_MSG_DISCONNECT = 1
            disconnect = self._build_disconnect_message(
                "Too many authentication failures"
            )
            await self._safe_write(writer, disconnect)

        except Exception as e:
            self._logger.log_event(conn_id, "error", str(e))
        finally:
            await self._close_writer(writer)

    def _extract_and_log_credentials(
        self, conn_id: int, ip: str, data: bytes
    ):
        """
        Attempt to extract username/password from raw SSH auth data.
        SSH auth is encrypted in the real protocol, but many bots
        and scanners use simplified auth that we can partially decode.
        """
        try:
            # Log raw data for analysis
            data_repr = data.hex()[:200]
            self._logger.log_event(conn_id, "auth_data", data_repr)

            # Try to find ASCII strings in the binary data
            # (username/password often appear as readable text in bot tools)
            ascii_parts = []
            current = []
            for byte in data:
                if 32 <= byte < 127:
                    current.append(chr(byte))
                else:
                    if len(current) >= 2:
                        ascii_parts.append("".join(current))
                    current = []
            if len(current) >= 2:
                ascii_parts.append("".join(current))

            if ascii_parts:
                self._logger.log_event(
                    conn_id, "auth_strings",
                    " | ".join(ascii_parts[:10])
                )

                # Heuristic: if we find 2+ strings, treat as user/pass
                if len(ascii_parts) >= 2:
                    username = ascii_parts[0]
                    password = ascii_parts[1]
                    self._logger.log_credentials(
                        conn_id, "ssh", ip, username, password
                    )
        except Exception:
            pass

    def _build_auth_failure(self) -> bytes:
        """Build SSH_MSG_USERAUTH_FAILURE packet."""
        # Type 51 = SSH_MSG_USERAUTH_FAILURE
        # Authentications that can continue: "password,keyboard-interactive"
        methods = b"password,keyboard-interactive"
        payload = bytes([51])
        payload += struct.pack(">I", len(methods)) + methods
        payload += bytes([0])  # partial_success = false
        return self._build_ssh_packet(payload)

    def _build_disconnect_message(self, reason: str) -> bytes:
        """Build SSH_MSG_DISCONNECT packet."""
        # Type 1 = SSH_MSG_DISCONNECT
        # Reason code 2 = SSH_DISCONNECT_PROTOCOL_ERROR
        reason_bytes = reason.encode("utf-8")
        payload = bytes([1])
        payload += struct.pack(">I", 2)  # reason code
        payload += struct.pack(">I", len(reason_bytes)) + reason_bytes
        payload += struct.pack(">I", 0)  # language tag (empty)
        return self._build_ssh_packet(payload)
