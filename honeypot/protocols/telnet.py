"""
Telnet Protocol Handler — Mimics Ubuntu 22.04.3 LTS login

Emulates a realistic Linux login flow:
- OS banner
- login: / Password: prompts
- Fake shell session after successful login (any credentials work on 3rd attempt)
- ~15 safe commands with hardcoded/templated responses
- Captures C2 addresses from wget/curl commands without executing
- Unknown commands return "bash: command not found"

All responses are string templates — no real shell or filesystem.
"""

import asyncio
import random
from datetime import datetime, timezone
from typing import Optional

from .base import BaseProtocolHandler
from ..config import ProtocolConfig
from ..logger import HoneypotLogger


class TelnetHandler(BaseProtocolHandler):
    """Fake Telnet login + shell mimicking Ubuntu 22.04 LTS."""

    PROTOCOL_NAME = "telnet"

    # Fake /etc/passwd content
    FAKE_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin"""

    # Bait: fake /etc/shadow with crackable-looking hashes (all fake)
    BAIT_SHADOW = """root:$6$rOoXk3Sj$z4BHMZ9J5jKfN7u3X8yL1wVtR5qE9mD2aG0hC4iB6nA8pY7xW0sU3fK9oL2jM5rT8eQ1cN4gH6dI7bA0wF3vX.:19691:0:99999:7:::
daemon:*:19400:0:99999:7:::
bin:*:19400:0:99999:7:::
sys:*:19400:0:99999:7:::
www-data:*:19400:0:99999:7:::
sshd:*:19400:0:99999:7:::
ubuntu:$6$pKrT8dE2$yR7wN9xH5jU3gF1vL0qZ8mB4sA6cD2eK7fJ9iG0hM3nO5rT1wP4uX8yV6bQ2aE9lC3dI7kF0jH5gN8mA4sR.:19691:0:99999:7:::
test:$6$mQ5rT1wP$uX8yV6bQ2aE9lC3dI7kF0jH5gN8mA4sRyR7wN9xH5jU3gF1vL0qZ8mB4sA6cD2eK7fJ9iG0hM3nO5rT1.:19691:0:99999:7:::"""

    # Fake process list
    FAKE_PS = """  PID TTY          TIME CMD
    1 ?        00:00:03 systemd
    2 ?        00:00:00 kthreadd
  456 ?        00:00:01 sshd
  789 ?        00:00:00 cron
  912 ?        00:00:02 rsyslogd
 1024 pts/0    00:00:00 bash
 1156 pts/0    00:00:00 ps"""

    # Fake network info
    FAKE_IFCONFIG = """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255
        inet6 fe80::a00:27ff:fe8e:1234  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:8e:12:34  txqueuelen 1000  (Ethernet)
        RX packets 12345  bytes 9876543 (9.8 MB)
        TX packets 6789  bytes 1234567 (1.2 MB)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)"""

    FAKE_NETSTAT = """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:25              0.0.0.0:*               LISTEN
tcp        0    196 10.0.2.15:23            {client_ip}:{client_port}  ESTABLISHED
udp        0      0 0.0.0.0:68              0.0.0.0:*"""

    FAKE_LS = """total 32
drwxr-xr-x  4 {user} {user} 4096 Mar 24 01:55 .
drwxr-xr-x  3 root   root   4096 Mar 15 10:30 ..
-rw-------  1 {user} {user}  220 Mar 15 10:30 .bash_history
-rw-r--r--  1 {user} {user}  220 Mar 15 10:30 .bash_logout
-rw-r--r--  1 {user} {user} 3771 Mar 15 10:30 .bashrc
drwxr-xr-x  2 {user} {user} 4096 Mar 15 10:30 .cache
-rw-r--r--  1 {user} {user}  807 Mar 15 10:30 .profile
drwx------  2 {user} {user} 4096 Mar 24 01:50 .ssh"""

    FAKE_W = """ {time} up 42 days,  3:15,  1 user,  load average: 0.08, 0.03, 0.01
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
{user}   pts/0    {client_ip}      {time}   0.00s  0.01s  0.00s w"""

    def __init__(self, config: ProtocolConfig, logger: HoneypotLogger):
        super().__init__(config, logger)
        self._hostname = config.hostname
        self._os_banner = config.os_banner
        self._fake_user = config.fake_user
        self._max_login_attempts = config.max_login_attempts

    async def handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        session_id: Optional[str] = None,
    ):
        """Handle a Telnet connection."""
        ip, port = self._get_peer_info(writer)
        conn_id = self._logger.log_connection("telnet", ip, port, session_id)

        try:
            # Telnet IAC negotiation (suppress go ahead, echo)
            # IAC WILL ECHO
            await self._safe_write(writer, bytes([255, 251, 1]))
            # IAC WILL SUPPRESS_GO_AHEAD
            await self._safe_write(writer, bytes([255, 251, 3]))
            # IAC DO TERMINAL_TYPE
            await self._safe_write(writer, bytes([255, 253, 24]))

            # Read and discard client's IAC responses
            await self._safe_read(reader, max_bytes=256, timeout=2.0)

            # Show OS banner
            await self._send_line(writer, self._os_banner)

            # Login loop
            authenticated_user = await self._login_loop(
                reader, writer, conn_id, ip
            )

            if authenticated_user:
                # Fake shell session
                await self._shell_session(
                    reader, writer, conn_id, ip, port,
                    authenticated_user
                )

        except Exception as e:
            self._logger.log_event(conn_id, "error", str(e))
        finally:
            await self._close_writer(writer)

    async def _login_loop(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        conn_id: int,
        ip: str,
    ) -> Optional[str]:
        """
        Run the login prompt loop.
        Returns the username if authenticated, None otherwise.
        Allows login on the last attempt to extend session.
        """
        for attempt in range(self._max_login_attempts):
            # Username prompt
            await self._safe_write(
                writer, f"{self._hostname} login: ".encode()
            )
            username_raw = await self._safe_readline(reader, timeout=30.0)
            if not username_raw:
                return None
            username = self._clean_telnet_input(username_raw)

            # Password prompt (disable echo)
            await self._safe_write(writer, b"Password: ")
            password_raw = await self._safe_readline(reader, timeout=30.0)
            if not password_raw:
                return None
            password = self._clean_telnet_input(password_raw)
            await self._send_line(writer, "")  # newline after hidden password

            # Log credentials
            self._logger.log_credentials(
                conn_id, "telnet", ip, username, password
            )

            # Allow login on last attempt to capture more intelligence
            if attempt == self._max_login_attempts - 1:
                now = datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S %Y")
                await self._send_line(
                    writer,
                    f"Last login: {now} from 10.0.0.1"
                )
                return username or self._fake_user
            else:
                await self._send_line(writer, "Login incorrect")
                await self._send_line(writer, "")

        return None

    async def _shell_session(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        conn_id: int,
        client_ip: str,
        client_port: int,
        username: str,
    ):
        """
        Fake shell session with ~15 safe commands.
        All responses are hardcoded/templated.
        """
        prompt = f"{username}@{self._hostname}:~$ "

        while True:
            await self._safe_write(writer, prompt.encode())

            cmd_raw = await self._safe_readline(reader, timeout=120.0)
            if not cmd_raw:
                break

            cmd_line = self._clean_telnet_input(cmd_raw)
            if not cmd_line:
                continue

            # Log every command
            self._logger.log_event(conn_id, "shell_command", cmd_line)

            # Parse command
            parts = cmd_line.split()
            cmd = parts[0].lower()
            args = parts[1:] if len(parts) > 1 else []

            # Handle commands
            output = self._execute_fake_command(
                cmd, args, username, client_ip, client_port, conn_id
            )

            if output is None:
                # exit command
                break

            # Bait: sudo/su escalation
            if output == "__SUDO_BAIT__":
                # Ask for password
                await self._safe_write(
                    writer, b"[sudo] password for " + username.encode() + b": "
                )
                pwd_raw = await self._safe_readline(reader, timeout=30.0)
                if pwd_raw:
                    sudo_pass = self._clean_telnet_input(pwd_raw)
                    self._logger.log_credential(
                        conn_id, username, sudo_pass
                    )
                    self._logger.log_event(
                        conn_id, "bait_triggered",
                        f"sudo escalation: {username}:{sudo_pass}"
                    )
                # Pretend success — switch to root prompt
                username = "root"
                prompt = f"root@{self._hostname}:~# "
                await self._send_line(writer, "")
                continue

            if output:
                await self._send_line(writer, output)

    def _execute_fake_command(
        self,
        cmd: str,
        args: list,
        username: str,
        client_ip: str,
        client_port: int,
        conn_id: int,
    ) -> Optional[str]:
        """
        Execute a fake command. Returns output string, empty string for no output,
        or None to signal exit.
        """
        now = datetime.now(timezone.utc).strftime("%H:%M:%S")

        if cmd in ("exit", "logout", "quit"):
            return None

        elif cmd == "whoami":
            return username

        elif cmd == "id":
            uid = 1001 if username != "root" else 0
            gid = uid
            groups = f"{gid}({username})"
            if username == "root":
                groups += ",0(root)"
            return f"uid={uid}({username}) gid={gid}({username}) groups={groups}"

        elif cmd == "uname":
            if "-a" in args:
                return (
                    "Linux honeypot-server 5.15.0-91-generic "
                    "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 "
                    "x86_64 x86_64 x86_64 GNU/Linux"
                )
            elif "-r" in args:
                return "5.15.0-91-generic"
            elif "-m" in args:
                return "x86_64"
            else:
                return "Linux"

        elif cmd == "pwd":
            return f"/home/{username}" if username != "root" else "/root"

        elif cmd == "ls":
            return self.FAKE_LS.format(user=username)

        elif cmd == "cat":
            if args:
                target = args[0]
                self._logger.log_event(
                    conn_id, "cat_target", target
                )
                if target == "/etc/passwd":
                    return self.FAKE_PASSWD
                elif target == "/etc/shadow":
                    # Bait: return fake shadow hashes (looks like root access)
                    self._logger.log_event(
                        conn_id, "bait_triggered", "shadow file read"
                    )
                    return self.BAIT_SHADOW
                elif target in ("/etc/hostname", "hostname"):
                    return self._hostname
                elif target == "/etc/os-release":
                    return (
                        'NAME="Ubuntu"\n'
                        'VERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
                        'ID=ubuntu\n'
                        'VERSION_ID="22.04"\n'
                        'PRETTY_NAME="Ubuntu 22.04.3 LTS"'
                    )
                else:
                    return f"cat: {target}: No such file or directory"
            return ""

        elif cmd == "ps":
            return self.FAKE_PS

        elif cmd == "w":
            return self.FAKE_W.format(
                time=now, user=username, client_ip=client_ip
            )

        elif cmd in ("ifconfig", "ip"):
            return self.FAKE_IFCONFIG

        elif cmd == "netstat":
            return self.FAKE_NETSTAT.format(
                client_ip=client_ip, client_port=client_port
            )

        elif cmd == "hostname":
            return self._hostname

        elif cmd in ("wget", "curl"):
            # Bait: simulate successful download (captures C2 URLs)
            url = args[0] if args else ""
            self._logger.log_event(conn_id, "c2_url", f"{cmd} {url}")
            self._logger.log_event(
                conn_id, "toolkit_download_attempt",
                " ".join([cmd] + args)
            )
            self._logger.log_event(conn_id, "bait_triggered", f"{cmd} download sim")

            if cmd == "wget":
                filename = url.split("/")[-1] if "/" in url else "index.html"
                host = url.split("/")[2] if len(url.split("/")) > 2 else "unknown"
                return (
                    f"--{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}--  {url}\n"
                    f"Resolving {host}... 93.184.216.34\n"
                    f"Connecting to {host}|93.184.216.34|:443... connected.\n"
                    f"HTTP request sent, awaiting response... 200 OK\n"
                    f"Length: 1337 (1.3K) [application/octet-stream]\n"
                    f"Saving to: '{filename}'\n"
                    f"\n"
                    f"     0K .                                                     100% 2.45M=0.001s\n"
                    f"\n"
                    f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} (2.45 MB/s) - '{filename}' saved [1337/1337]"
                )
            else:
                return ""  # curl outputs content to stdout (silent)

        elif cmd == "cd":
            return ""  # silently accept

        elif cmd == "echo":
            return " ".join(args)

        elif cmd == "help":
            return (
                "GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)\n"
                "These shell commands are defined internally. Type 'help' to see this list."
            )

        elif cmd == "history":
            return (
                "    1  ls\n"
                "    2  whoami\n"
                "    3  id\n"
                f"    4  {cmd} {' '.join(args)}"
            )

        elif cmd in ("sudo", "su"):
            # Bait: ask for password, pretend to succeed, log escalation
            return "__SUDO_BAIT__"  # sentinel handled in _shell_session

        elif cmd in ("chmod", "chown", "rm", "mv", "cp", "mkdir", "touch"):
            if cmd == "rm" and ("-rf" in args or "-r" in args):
                self._logger.log_event(
                    conn_id, "destructive_command",
                    f"{cmd} {' '.join(args)}"
                )
            return f"{cmd}: operation not permitted"

        elif cmd in ("python", "python3", "perl", "php", "ruby", "node"):
            self._logger.log_event(
                conn_id, "interpreter_attempt",
                f"{cmd} {' '.join(args)}"
            )
            return f"bash: {cmd}: command not found"

        elif cmd in ("nc", "ncat", "netcat"):
            self._logger.log_event(
                conn_id, "netcat_attempt",
                f"{cmd} {' '.join(args)}"
            )
            return f"bash: {cmd}: command not found"

        elif cmd in ("gcc", "cc", "make"):
            self._logger.log_event(
                conn_id, "compile_attempt",
                f"{cmd} {' '.join(args)}"
            )
            return f"bash: {cmd}: command not found"

        else:
            self._logger.log_event(
                conn_id, "unknown_command",
                f"{cmd} {' '.join(args)}"
            )
            return f"bash: {cmd}: command not found"

    def _clean_telnet_input(self, data: bytes) -> str:
        """Remove Telnet IAC sequences and clean input."""
        result = []
        i = 0
        raw = data
        while i < len(raw):
            if raw[i] == 255 and i + 1 < len(raw):
                # IAC sequence — skip 2 or 3 bytes
                if raw[i + 1] in (251, 252, 253, 254) and i + 2 < len(raw):
                    i += 3
                else:
                    i += 2
            elif raw[i] == 0:
                i += 1  # skip NUL
            else:
                result.append(raw[i])
                i += 1

        return bytes(result).decode("utf-8", errors="replace").strip()

    async def _send_line(
        self, writer: asyncio.StreamWriter, text: str
    ):
        """Send a line of text with CRLF."""
        await self._safe_write(writer, (text + "\r\n").encode())
