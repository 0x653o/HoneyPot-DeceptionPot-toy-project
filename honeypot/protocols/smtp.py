"""
SMTP Protocol Handler — Mimics Postfix 3.6 (Ubuntu)

Emulates a realistic SMTP dialog:
- EHLO with full capability list (PIPELINING, STARTTLS, AUTH, etc.)
- AUTH LOGIN / AUTH PLAIN with base64 credential capture
- MAIL FROM / RCPT TO / DATA flow
- Generates fake queue IDs
- Captures entire message bodies, sender/receiver, auth credentials

All responses are string templates — no real mail relay.
"""

import asyncio
import base64
import hashlib
import os
import random
import string
from typing import Optional

from .base import BaseProtocolHandler
from ..config import ProtocolConfig
from ..logger import HoneypotLogger


class SMTPHandler(BaseProtocolHandler):
    """Fake SMTP server mimicking Postfix 3.6 (Ubuntu)."""

    PROTOCOL_NAME = "smtp"

    EHLO_CAPABILITIES = [
        "PIPELINING",
        "SIZE {max_size}",
        "VRFY",
        "ETRN",
        "STARTTLS",
        "AUTH PLAIN LOGIN CRAM-MD5",
        "ENHANCEDSTATUSCODES",
        "8BITMIME",
        "DSN",
        "SMTPUTF8",
        "CHUNKING",
    ]

    def __init__(self, config: ProtocolConfig, logger: HoneypotLogger):
        super().__init__(config, logger)
        self._hostname = config.hostname
        self._max_message_size = config.max_message_size
        banner = config.banner or f"220 {self._hostname} ESMTP Postfix (Ubuntu)"
        if not banner.startswith("220"):
            banner = f"220 {banner}"
        self._banner = banner

    async def handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        session_id: Optional[str] = None,
    ):
        """Handle an SMTP connection."""
        ip, port = self._get_peer_info(writer)
        conn_id = self._logger.log_connection("smtp", ip, port, session_id)

        authenticated = False
        mail_from = None
        rcpt_to = []
        ehlo_hostname = None

        try:
            # Send greeting
            await self._send_response(writer, self._banner)

            while True:
                line = await self._safe_readline(reader, timeout=60.0)
                if not line:
                    break

                cmd_line = line.decode("utf-8", errors="replace").strip()
                if not cmd_line:
                    continue

                # Log every command
                self._logger.log_event(conn_id, "smtp_command", cmd_line)

                # Parse command
                parts = cmd_line.split(" ", 1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""

                # --- EHLO / HELO ---
                if cmd in ("EHLO", "HELO"):
                    ehlo_hostname = arg
                    self._logger.log_event(
                        conn_id, "ehlo_hostname", ehlo_hostname
                    )

                    if cmd == "EHLO":
                        # Multi-line EHLO response
                        await self._send_response(
                            writer, f"250-{self._hostname}"
                        )
                        caps = self.EHLO_CAPABILITIES[:]
                        for i, cap in enumerate(caps[:-1]):
                            cap_line = cap.format(
                                max_size=self._max_message_size
                            )
                            await self._send_response(
                                writer, f"250-{cap_line}"
                            )
                        # Last capability without dash
                        last_cap = caps[-1].format(
                            max_size=self._max_message_size
                        )
                        await self._send_response(
                            writer, f"250 {last_cap}"
                        )
                    else:
                        await self._send_response(
                            writer,
                            f"250 {self._hostname}, I am glad to meet you"
                        )

                # --- AUTH ---
                elif cmd == "AUTH":
                    await self._handle_auth(
                        reader, writer, conn_id, ip, arg
                    )
                    authenticated = True  # Always say success to capture more

                # --- STARTTLS ---
                elif cmd == "STARTTLS":
                    await self._send_response(
                        writer, "220 2.0.0 Ready to start TLS"
                    )
                    # We can't actually do TLS, but some bots
                    # continue with EHLO after this
                    self._logger.log_event(
                        conn_id, "starttls_attempted", "true"
                    )

                # --- MAIL FROM ---
                elif cmd == "MAIL" and arg.upper().startswith("FROM:"):
                    mail_from = arg[5:].strip().strip("<>")
                    self._logger.log_event(
                        conn_id, "mail_from", mail_from
                    )
                    await self._send_response(
                        writer, "250 2.1.0 Ok"
                    )

                # --- RCPT TO ---
                elif cmd == "RCPT" and arg.upper().startswith("TO:"):
                    recipient = arg[3:].strip().strip("<>")
                    rcpt_to.append(recipient)
                    self._logger.log_event(
                        conn_id, "rcpt_to", recipient
                    )

                    # Bait: open relay — accept any domain
                    # This encourages spammers to try sending through us
                    domain = recipient.split("@")[-1] if "@" in recipient else ""
                    if domain and domain != self._hostname:
                        self._logger.log_event(
                            conn_id, "bait_triggered",
                            f"open relay: external domain {domain}"
                        )

                    await self._send_response(
                        writer, "250 2.1.5 Ok"
                    )

                # --- DATA ---
                elif cmd == "DATA":
                    await self._send_response(
                        writer,
                        "354 End data with <CR><LF>.<CR><LF>"
                    )

                    # Read message body until lone "."
                    message_body = await self._read_data_body(reader)

                    self._logger.log_event(
                        conn_id, "smtp_message_body",
                        message_body[:4096]  # Cap logged body
                    )

                    # Log full email metadata
                    self._logger.log_event(
                        conn_id, "smtp_email_meta",
                        f"FROM={mail_from} TO={','.join(rcpt_to)} "
                        f"SIZE={len(message_body)}"
                    )

                    # Generate fake queue ID
                    queue_id = self._generate_queue_id()
                    await self._send_response(
                        writer,
                        f"250 2.0.0 Ok: queued as {queue_id}"
                    )

                    # Reset for next message
                    mail_from = None
                    rcpt_to = []

                # --- VRFY ---
                elif cmd == "VRFY":
                    # Bait: confirm any user exists — attracts email harvesters
                    self._logger.log_event(
                        conn_id, "vrfy_attempt", arg
                    )
                    self._logger.log_event(
                        conn_id, "bait_triggered",
                        f"vrfy confirmed: {arg}"
                    )
                    user = arg.strip().strip("<>")
                    await self._send_response(
                        writer,
                        f"250 2.0.0 {user} <{user}@{self._hostname}>"
                    )

                # --- EXPN ---
                elif cmd == "EXPN":
                    await self._send_response(
                        writer,
                        "252 2.1.0 Administrative prohibition"
                    )

                # --- RSET ---
                elif cmd == "RSET":
                    mail_from = None
                    rcpt_to = []
                    await self._send_response(
                        writer, "250 2.0.0 Ok"
                    )

                # --- NOOP ---
                elif cmd == "NOOP":
                    await self._send_response(
                        writer, "250 2.0.0 Ok"
                    )

                # --- QUIT ---
                elif cmd == "QUIT":
                    await self._send_response(
                        writer, "221 2.0.0 Bye"
                    )
                    break

                # --- Unknown ---
                else:
                    await self._send_response(
                        writer,
                        f"502 5.5.2 Error: command not recognized"
                    )

        except Exception as e:
            self._logger.log_event(conn_id, "error", str(e))
        finally:
            await self._close_writer(writer)

    async def _handle_auth(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        conn_id: int,
        ip: str,
        auth_arg: str,
    ):
        """
        Handle AUTH LOGIN / AUTH PLAIN commands.
        Decodes base64 credentials and logs them.
        """
        parts = auth_arg.split(" ", 1)
        method = parts[0].upper() if parts else ""
        initial_response = parts[1] if len(parts) > 1 else None

        if method == "LOGIN":
            # AUTH LOGIN flow
            # Step 1: Request username
            # "VXNlcm5hbWU6" = base64("Username:")
            await self._send_response(writer, "334 VXNlcm5hbWU6")

            user_line = await self._safe_readline(reader, timeout=30.0)
            if not user_line:
                return
            username = self._decode_base64(
                user_line.decode("utf-8", errors="replace").strip()
            )

            # Step 2: Request password
            # "UGFzc3dvcmQ6" = base64("Password:")
            await self._send_response(writer, "334 UGFzc3dvcmQ6")

            pass_line = await self._safe_readline(reader, timeout=30.0)
            if not pass_line:
                return
            password = self._decode_base64(
                pass_line.decode("utf-8", errors="replace").strip()
            )

            # Log credentials
            self._logger.log_credentials(
                conn_id, "smtp", ip, username, password
            )

            await self._send_response(
                writer, "235 2.7.0 Authentication successful"
            )

        elif method == "PLAIN":
            if initial_response:
                # Credentials provided inline
                self._decode_plain_auth(
                    conn_id, ip, initial_response
                )
            else:
                # Request credentials
                await self._send_response(writer, "334")
                cred_line = await self._safe_readline(reader, timeout=30.0)
                if cred_line:
                    self._decode_plain_auth(
                        conn_id, ip,
                        cred_line.decode("utf-8", errors="replace").strip()
                    )

            await self._send_response(
                writer, "235 2.7.0 Authentication successful"
            )

        elif method == "CRAM-MD5":
            # Send challenge
            challenge = base64.b64encode(
                f"<{self._generate_queue_id()}@{self._hostname}>".encode()
            ).decode()
            await self._send_response(writer, f"334 {challenge}")

            response_line = await self._safe_readline(reader, timeout=30.0)
            if response_line:
                decoded = self._decode_base64(
                    response_line.decode("utf-8", errors="replace").strip()
                )
                self._logger.log_event(
                    conn_id, "cram_md5_response", decoded
                )

            await self._send_response(
                writer, "235 2.7.0 Authentication successful"
            )

        else:
            await self._send_response(
                writer,
                "504 5.5.4 Unrecognized authentication type"
            )

    def _decode_plain_auth(
        self, conn_id: int, ip: str, encoded: str
    ):
        """Decode AUTH PLAIN credentials (base64 encoded \0user\0pass)."""
        try:
            decoded = base64.b64decode(encoded).decode("utf-8", errors="replace")
            parts = decoded.split("\0")
            if len(parts) >= 3:
                username = parts[1]
                password = parts[2]
            elif len(parts) >= 2:
                username = parts[0]
                password = parts[1]
            else:
                username = decoded
                password = ""

            self._logger.log_credentials(
                conn_id, "smtp", ip, username, password
            )
        except Exception:
            self._logger.log_event(
                conn_id, "auth_plain_raw", encoded
            )

    def _decode_base64(self, encoded: str) -> str:
        """Safely decode a base64 string."""
        try:
            return base64.b64decode(encoded).decode("utf-8", errors="replace")
        except Exception:
            return encoded

    async def _read_data_body(
        self, reader: asyncio.StreamReader
    ) -> str:
        """Read SMTP DATA body until lone '.' on a line."""
        lines = []
        total_size = 0
        max_size = self._max_message_size

        while total_size < max_size:
            line = await self._safe_readline(reader, timeout=60.0)
            if not line:
                break

            line_str = line.decode("utf-8", errors="replace").rstrip("\r\n")

            if line_str == ".":
                break

            # Handle dot-stuffing (RFC 5321 4.5.2)
            if line_str.startswith(".."):
                line_str = line_str[1:]

            lines.append(line_str)
            total_size += len(line_str)

        return "\n".join(lines)

    def _generate_queue_id(self) -> str:
        """Generate a realistic Postfix queue ID."""
        chars = string.ascii_uppercase + string.digits
        return "".join(random.choice(chars) for _ in range(10))

    async def _send_response(
        self, writer: asyncio.StreamWriter, response: str
    ):
        """Send an SMTP response line with CRLF."""
        await self._safe_write(writer, (response + "\r\n").encode())
