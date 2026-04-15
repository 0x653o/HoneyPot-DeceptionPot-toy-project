"""
FTP Protocol Handler — Mimics vsftpd 3.0.5

Emulates a real FTP session with:
- Greeting banner
- USER/PASS authentication (captures credentials)
- Anonymous login support (extends session for intelligence)
- LIST command with fake directory listing
- RETR command with fake file content
- Full FTP command dialog (SYST, TYPE, PWD, CWD, PASV, etc.)

All responses are string templates — no real filesystem access.
"""

import asyncio
import random
from typing import Optional

from .base import BaseProtocolHandler
from ..config import ProtocolConfig
from ..logger import HoneypotLogger


class FTPHandler(BaseProtocolHandler):
    """Fake FTP server mimicking vsftpd 3.0.5."""

    PROTOCOL_NAME = "ftp"

    FAKE_DIRECTORY = [
        "drwxr-xr-x    2 0        0            4096 Mar 15 10:30 pub",
        "drwxrwxrwx    2 0        0            4096 Mar 22 14:50 upload",
        "-rw-r--r--    1 0        0            1024 Mar 10 08:15 welcome.txt",
        "-rw-r--r--    1 0        0           23456 Feb 28 14:22 readme.md",
        "-rw-r--r--    1 0        0             512 Jan 15 09:00 .htaccess",
        "-rw-------    1 root     root        84921 Mar 20 03:00 backup.sql",
        "-rw-------    1 root     root          412 Mar 18 11:30 credentials.txt",
    ]

    FAKE_PUB_DIRECTORY = [
        "-rw-r--r--    1 0        0           45678 Mar 01 12:00 archive.tar.gz",
        "-rw-r--r--    1 0        0            8192 Feb 15 16:30 data.csv",
        "-rw-r--r--    1 0        0            2048 Feb 10 11:00 notes.txt",
    ]

    FAKE_UPLOAD_DIRECTORY = [
        "-rw-r--r--    1 ftp      ftp          1337 Mar 21 09:15 test.txt",
    ]

    FAKE_FILE_CONTENT = (
        "Welcome to the FTP server.\n"
        "This server is maintained by the system administrator.\n"
        "Please contact admin@example.com for any issues.\n"
        "\n"
        "Last updated: 2026-03-15\n"
    )

    # Bait: fake sensitive file contents (pure string templates)
    BAIT_BACKUP_SQL = (
        "-- MySQL dump 10.13  Distrib 8.0.35, for Linux (x86_64)\n"
        "-- Host: 127.0.0.1    Database: webapp_production\n"
        "-- Server version\t8.0.35-0ubuntu0.22.04.1\n"
        "--\n"
        "-- Table structure for table `users`\n"
        "--\n"
        "CREATE TABLE `users` (\n"
        "  `id` int NOT NULL AUTO_INCREMENT,\n"
        "  `email` varchar(255) NOT NULL,\n"
        "  `password` varchar(255) NOT NULL,\n"
        "  `role` enum('user','admin') DEFAULT 'user',\n"
        "  PRIMARY KEY (`id`)\n"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n"
        "\n"
        "INSERT INTO `users` VALUES\n"
        "(1,'admin@example.com','$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy','admin'),\n"
        "(2,'john@example.com','$2b$10$R4d7IkEy4oGe5k3q1yP8yOjZ1T5F5G6H7J8K9L0M1N2O3P4Q5R6S','user'),\n"
        "(3,'deploy@example.com','$2b$10$A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6','admin');\n"
    )

    BAIT_CREDENTIALS_TXT = (
        "# Internal Service Credentials\n"
        "# DO NOT commit this file!\n"
        "\n"
        "MySQL Root: root / M4st3r_R00t!2024\n"
        "Redis: (no auth)\n"
        "Grafana: admin / Gr4f4n4_Adm1n\n"
        "Jenkins: deploy / J3nk1ns_D3pl0y!\n"
        "SSH (deploy): deploy / d3pl0y_k3y_2024\n"
    )

    def __init__(self, config: ProtocolConfig, logger: HoneypotLogger):
        super().__init__(config, logger)
        self._allow_anonymous = config.allow_anonymous
        banner = config.banner or "220 (vsFTPd 3.0.5)"
        # Ensure banner starts with 220
        if not banner.startswith("220"):
            banner = f"220 {banner}"
        self._banner = banner

    async def handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        session_id: Optional[str] = None,
    ):
        """Handle an FTP connection."""
        ip, port = self._get_peer_info(writer)
        conn_id = self._logger.log_connection("ftp", ip, port, session_id)

        authenticated = False
        current_user = None
        current_dir = "/"

        try:
            # Send greeting
            await self._send_response(writer, self._banner)

            while True:
                line = await self._safe_readline(reader, timeout=60.0)
                if not line:
                    break

                command_line = line.decode("utf-8", errors="replace").strip()
                if not command_line:
                    continue

                # Log every command
                self._logger.log_event(conn_id, "ftp_command", command_line)

                # Parse command and argument
                parts = command_line.split(" ", 1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""

                # Route FTP commands
                if cmd == "USER":
                    current_user = arg
                    await self._send_response(
                        writer, "331 Please specify the password."
                    )

                elif cmd == "PASS":
                    password = arg
                    if current_user:
                        self._logger.log_credentials(
                            conn_id, "ftp", ip,
                            current_user, password
                        )

                    if (
                        self._allow_anonymous
                        and current_user
                        and current_user.lower() == "anonymous"
                    ):
                        authenticated = True
                        await self._send_response(
                            writer, "230 Login successful."
                        )
                    else:
                        await self._send_response(
                            writer, "530 Login incorrect."
                        )
                        # Allow retry
                        current_user = None

                elif cmd == "SYST":
                    await self._send_response(
                        writer, "215 UNIX Type: L8"
                    )

                elif cmd == "FEAT":
                    await self._send_response(
                        writer,
                        "211-Features:\r\n"
                        " EPRT\r\n"
                        " EPSV\r\n"
                        " MDTM\r\n"
                        " PASV\r\n"
                        " REST STREAM\r\n"
                        " SIZE\r\n"
                        " TVFS\r\n"
                        " UTF8\r\n"
                        "211 End"
                    )

                elif cmd == "TYPE":
                    await self._send_response(
                        writer,
                        f"200 Switching to {arg or 'Binary'} mode."
                    )

                elif cmd == "PWD" or cmd == "XPWD":
                    await self._send_response(
                        writer, f'257 "{current_dir}" is the current directory'
                    )

                elif cmd == "CWD" or cmd == "XCWD":
                    if arg in ("/", "/pub", "/upload"):
                        current_dir = arg if arg != "" else "/"
                        self._logger.log_event(
                            conn_id, "ftp_cwd", current_dir
                        )
                        await self._send_response(
                            writer, "250 Directory successfully changed."
                        )
                    else:
                        await self._send_response(
                            writer, "550 Failed to change directory."
                        )

                elif cmd == "PASV":
                    # Generate fake PASV response
                    p1 = random.randint(128, 250)
                    p2 = random.randint(1, 254)
                    await self._send_response(
                        writer,
                        f"227 Entering Passive Mode (127,0,0,1,{p1},{p2})."
                    )

                elif cmd == "EPSV":
                    fake_port = random.randint(32768, 60999)
                    await self._send_response(
                        writer,
                        f"229 Entering Extended Passive Mode (|||{fake_port}|)."
                    )

                elif cmd == "LIST" or cmd == "NLST":
                    if not authenticated:
                        await self._send_response(
                            writer, "530 Please login with USER and PASS."
                        )
                        continue

                    await self._send_response(
                        writer,
                        "150 Here comes the directory listing."
                    )

                    listing = self.FAKE_DIRECTORY
                    if current_dir == "/pub":
                        listing = self.FAKE_PUB_DIRECTORY
                    elif current_dir == "/upload":
                        listing = self.FAKE_UPLOAD_DIRECTORY

                    for entry in listing:
                        await self._safe_write(
                            writer, (entry + "\r\n").encode()
                        )

                    await self._send_response(
                        writer, "226 Directory send OK."
                    )

                elif cmd == "RETR":
                    if not authenticated:
                        await self._send_response(
                            writer, "530 Please login with USER and PASS."
                        )
                        continue

                    self._logger.log_event(
                        conn_id, "ftp_download", arg
                    )

                    # Serve bait content for sensitive-looking files
                    if arg in ("backup.sql", "/backup.sql"):
                        content = self.BAIT_BACKUP_SQL
                        self._logger.log_event(conn_id, "bait_triggered", f"ftp retr: {arg}")
                    elif arg in ("credentials.txt", "/credentials.txt"):
                        content = self.BAIT_CREDENTIALS_TXT
                        self._logger.log_event(conn_id, "bait_triggered", f"ftp retr: {arg}")
                    else:
                        content = self.FAKE_FILE_CONTENT
                    await self._send_response(
                        writer,
                        f"150 Opening BINARY mode data connection for "
                        f"{arg} ({len(content)} bytes)."
                    )
                    await self._safe_write(writer, content.encode())
                    await self._send_response(
                        writer, "226 Transfer complete."
                    )

                elif cmd == "STOR":
                    if not authenticated:
                        await self._send_response(
                            writer, "530 Please login with USER and PASS."
                        )
                        continue

                    self._logger.log_event(
                        conn_id, "ftp_upload_attempt", arg
                    )

                    # Bait: writable /upload dir — accept the upload (fake)
                    if current_dir == "/upload" or arg.startswith("/upload/"):
                        self._logger.log_event(
                            conn_id, "bait_triggered",
                            f"ftp upload accepted (fake): {arg}"
                        )
                        # Read whatever the client sends as the file
                        upload_data = await self._safe_read(
                            reader, max_bytes=65536, timeout=10.0
                        )
                        if upload_data:
                            self._logger.log_event(
                                conn_id, "ftp_upload_data",
                                upload_data[:2048].hex()
                            )
                        await self._send_response(
                            writer, "226 Transfer complete."
                        )
                    else:
                        await self._send_response(
                            writer, "553 Could not create file."
                        )

                elif cmd == "SIZE":
                    if arg.endswith(".txt"):
                        await self._send_response(
                            writer, f"213 {len(self.FAKE_FILE_CONTENT)}"
                        )
                    else:
                        await self._send_response(
                            writer, "550 Could not get file size."
                        )

                elif cmd == "MDTM":
                    await self._send_response(
                        writer, "213 20260315103000"
                    )

                elif cmd == "NOOP":
                    await self._send_response(writer, "200 NOOP ok.")

                elif cmd == "QUIT":
                    await self._send_response(writer, "221 Goodbye.")
                    break

                elif cmd == "HELP":
                    await self._send_response(
                        writer,
                        "214-The following commands are recognized.\r\n"
                        " CWD FEAT HELP LIST MDTM NLST NOOP PASS PASV\r\n"
                        " PWD QUIT RETR SIZE STOR SYST TYPE USER\r\n"
                        "214 Help OK."
                    )

                else:
                    await self._send_response(
                        writer, f"500 Unknown command."
                    )

        except Exception as e:
            self._logger.log_event(conn_id, "error", str(e))
        finally:
            await self._close_writer(writer)

    async def _send_response(
        self, writer: asyncio.StreamWriter, response: str
    ):
        """Send an FTP response line with CRLF."""
        await self._safe_write(writer, (response + "\r\n").encode())
