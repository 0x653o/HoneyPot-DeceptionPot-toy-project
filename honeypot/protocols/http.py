"""
HTTP Protocol Handler — Mimics Apache 2.4.58 (Ubuntu)

Handles all standard HTTP methods (GET, POST, HEAD, OPTIONS, PUT, DELETE)
with production-grade headers and realistic response bodies.
Captures credentials from POST forms, Authorization headers, and cookies.

All responses are hardcoded templates — no real web server.
"""

import asyncio
import hashlib
import os
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Optional

from .base import BaseProtocolHandler
from ..config import ProtocolConfig
from ..logger import HoneypotLogger


class HTTPHandler(BaseProtocolHandler):
    """Fake HTTP server mimicking Apache 2.4.58 (Ubuntu)."""

    PROTOCOL_NAME = "http"

    # Realistic Apache default page (Ubuntu)
    DEFAULT_PAGE = """<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
   "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Apache2 Ubuntu Default Page: It works</title>
<style type="text/css" media="screen">
  * { margin: 0px 0px 0px 0px; padding: 0px 0px 0px 0px; }
  body, html { padding: 3px 3px 3px 3px; background-color: #D8DBE2;
    font-family: Ubuntu, Verdana, sans-serif; font-size: 11pt; text-align: center; }
  div.main_page { position: relative; display: table;
    width: 800px; margin-bottom: 3px; margin-left: auto; margin-right: auto;
    padding: 0px 0px 0px 0px; border-width: 2px; border-color: #212738;
    border-style: solid; background-color: #FFFFFF; }
  div.page_header { height: 99px; width: 100%; background-color: #F5F6F7; }
  div.page_header span { margin: 15px 0px 0px 50px; font-size: 180%;
    font-weight: bold; }
  div.page_header img { margin: 3px 0px 0px 40px;
    border: 0px 0px 0px; }
  div.banner { padding: 9px 6px 9px 6px;
    background-color: #A2AAB3; }
  div.banner span { font-weight: bold; font-size: 100%;
    color: #000000; }
  div.table_of_contents { clear: left; min-width: 200px;
    padding: 2px 2px 2px 2px; background-color: #FFFFFF; }
  div.content_section { padding: 6px; background-color: #FFFFFF; }
  div.content_section_text { padding: 4px 8px 4px 8px; color: #000000;
    font-size: 100%; }
  div.content_section_text pre { padding: 8px 8px 8px 8px;
    background-color: #F5F6F7; border: 1px solid #DCDDDE; }
  div.page_footer { padding-top: 4px; background-color: #F5F6F7; }
</style>
</head>
<body>
<div class="main_page">
  <div class="page_header floating_element">
    <span class="page_header_text">Apache2 Ubuntu Default Page</span>
  </div>
  <div class="banner">
    <span>It works!</span>
  </div>
  <div class="content_section floating_element">
    <div class="content_section_text">
      <p>This is the default welcome page used to test the correct operation
         of the Apache2 server after installation on Ubuntu systems. It is
         based on the equivalent page on Debian, from which the Ubuntu project
         is derived.</p>
      <p>If you can read this page, it means that the Apache HTTP server
         installed at this site is working properly. You should
         <b>replace this file</b> (located at
         <tt>/var/www/html/index.html</tt>) before continuing to operate
         your HTTP server.</p>
    </div>
  </div>
  <div class="content_section floating_element">
    <div class="content_section_text">
      <p>If you are a normal user of this web site and don't know what this
         page is about, this probably means that the site is currently
         unavailable due to maintenance. If the problem persists, please
         contact the site's administrator.</p>
    </div>
  </div>
  <div class="page_footer floating_element">
    <p>Apache/2.4.58 (Ubuntu) Server at {hostname} Port {port}</p>
  </div>
</div>
</body>
</html>"""

    NOT_FOUND_PAGE = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL {path} was not found on this server.</p>
<hr>
<address>Apache/2.4.58 (Ubuntu) Server at {hostname} Port {port}</address>
</body></html>"""

    METHOD_NOT_ALLOWED_PAGE = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>405 Method Not Allowed</title>
</head><body>
<h1>Method Not Allowed</h1>
<p>The requested method {method} is not allowed for the URL {path}.</p>
<hr>
<address>Apache/2.4.58 (Ubuntu) Server at {hostname} Port {port}</address>
</body></html>"""

    FORBIDDEN_PAGE = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access {path} on this server.</p>
<hr>
<address>Apache/2.4.58 (Ubuntu) Server at {hostname} Port {port}</address>
</body></html>"""

    # ================================================================
    # BAIT VULNERABILITY TEMPLATES
    # All content below is FAKE — designed to attract and log attackers.
    # No real credentials, no real files, no real execution.
    # ================================================================

    BAIT_ENV_FILE = """APP_NAME=Laravel
APP_ENV=production
APP_KEY=base64:k8BHwobcX2GpILEjzR/VN5JG+Yb8hTxGqV4fKg8OiWE=
APP_DEBUG=true
APP_URL=http://{hostname}

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=webapp_production
DB_USERNAME=webapp_user
DB_PASSWORD=Sup3r_S3cret_DB!2024

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=null
REDIS_PORT=6379

MAIL_MAILER=smtp
MAIL_HOST=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=admin@{hostname}
MAIL_PASSWORD=gmail_app_pass_fake123

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7FAKE123
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKEKEY999
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=webapp-assets-prod
"""

    BAIT_GIT_CONFIG = """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = https://github.com/company-internal/webapp-production.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
[user]
\tname = deploy-bot
\temail = deploy@{hostname}
"""

    BAIT_WP_CONFIG = """<?php
define( 'DB_NAME', 'wordpress_prod' );
define( 'DB_USER', 'wp_admin' );
define( 'DB_PASSWORD', 'W0rdPr3ss_Pr0d!2024' );
define( 'DB_HOST', '127.0.0.1' );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'DB_COLLATE', '' );

define( 'AUTH_KEY',         'put your unique phrase here' );
define( 'SECURE_AUTH_KEY',  'put your unique phrase here' );
define( 'LOGGED_IN_KEY',    'put your unique phrase here' );
define( 'NONCE_KEY',        'put your unique phrase here' );

$table_prefix = 'wp_';
define( 'WP_DEBUG', true );
define( 'WP_DEBUG_LOG', true );
define( 'ABSPATH', __DIR__ . '/' );
require_once ABSPATH . 'wp-settings.php';
"""

    BAIT_WP_LOGIN = """<!DOCTYPE html>
<html lang="en-US">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Log In &lsaquo; {hostname} &#8212; WordPress</title>
<style type="text/css">
body {{ background: #f1f1f1; font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif; }}
#login {{ width: 320px; margin: 80px auto; padding: 20px 0; }}
#login h1 a {{ background-image: url(data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0MDAgNDAwIj48cGF0aCBmaWxsPSIjMDA3M2FhIiBkPSJNMjAwIDBDODkuNyAwIDAgODkuNyAwIDIwMHM4OS43IDIwMCAyMDAgMjAwIDIwMC04OS43IDIwMC0yMDBTMzEwLjMgMCAyMDAgMHoiLz48L3N2Zz4=);
  background-size: 84px; width: 84px; height: 84px; display: block; margin: 0 auto 20px; text-indent: -9999px; }}
.login form {{ margin-top: 20px; padding: 26px 24px; background: #fff; border: 1px solid #c3c4c7; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,.04); }}
.login label {{ display: block; margin-bottom: 3px; font-size: 14px; }}
.login input[type=text], .login input[type=password] {{ width: 100%; padding: 3px 5px; margin: 2px 6px 16px 0; font-size: 24px; border: 1px solid #8c8f94; border-radius: 4px; box-sizing: border-box; }}
.login .button-primary {{ width: 100%; padding: 6px; font-size: 14px; background: #2271b1; border: 1px solid #2271b1; border-radius: 3px; color: #fff; cursor: pointer; }}
.login .button-primary:hover {{ background: #135e96; }}
</style>
</head>
<body class="login">
<div id="login">
<h1><a href="https://wordpress.org/">WordPress</a></h1>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login" value="" size="20" autocapitalize="off" /></p>
<p><label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass" value="" size="20" /></p>
<p class="forgetmenot"><label><input name="rememberme" type="checkbox" id="rememberme" value="forever" /> Remember Me</label></p>
<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button button-primary" value="Log In" /></p>
</form>
<p id="nav"><a href="/wp-login.php?action=lostpassword">Lost your password?</a></p>
</div>
</body>
</html>"""

    BAIT_PHPINFO = """<!DOCTYPE html>
<html>
<head><title>phpinfo()</title>
<style>body {{background-color: #fff; color: #222; font-family: sans-serif;}}
pre {{margin: 0; font-family: monospace;}}
table {{border-collapse: collapse; border: 0; width: 934px; box-shadow: 1px 2px 3px #ccc;}}
.center {{text-align: center;}} .center table {{margin: 1em auto; text-align: left;}}
td, th {{border: 1px solid #666; font-size: 75%; vertical-align: baseline; padding: 4px 5px;}}
h1 {{font-size: 150%;}}
h2 {{font-size: 125%;}}
.p {{text-align: left;}}
.e {{background-color: #ccf; width: 300px; font-weight: bold;}}
.v {{background-color: #ddd; max-width: 300px; overflow-x: auto; word-wrap: break-word;}}
.h {{background-color: #9999cc; font-weight: bold; color: #000;}}
hr {{width: 934px; background-color: #ccc; border: 0; height: 1px;}}
</style>
</head>
<body>
<div class="center">
<table><tr class="h"><td><h1 class="p">PHP Version 8.1.27</h1></td></tr></table>
<table><tr><td class="e">System</td><td class="v">Linux {hostname} 5.15.0-91-generic #101-Ubuntu SMP x86_64</td></tr>
<tr><td class="e">Build Date</td><td class="v">Dec 19 2023 20:35:02</td></tr>
<tr><td class="e">Server API</td><td class="v">Apache 2.0 Handler</td></tr>
<tr><td class="e">Document Root</td><td class="v">/var/www/html</td></tr>
<tr><td class="e">REMOTE_ADDR</td><td class="v">{client_ip}</td></tr>
<tr><td class="e">SERVER_SOFTWARE</td><td class="v">Apache/2.4.58 (Ubuntu)</td></tr>
<tr><td class="e">SERVER_NAME</td><td class="v">{hostname}</td></tr>
<tr><td class="e">SERVER_PORT</td><td class="v">{port}</td></tr>
<tr><td class="e">PHP_SELF</td><td class="v">/phpinfo.php</td></tr>
</table>
<h2>Configuration</h2>
<table><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">allow_url_fopen</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">allow_url_include</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">display_errors</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">upload_max_filesize</td><td class="v">64M</td><td class="v">64M</td></tr>
<tr><td class="e">max_execution_time</td><td class="v">30</td><td class="v">30</td></tr>
<tr><td class="e">disable_functions</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">open_basedir</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
</table>
<h2>mysql</h2>
<table><tr><td class="e">Active Persistent Links</td><td class="v">0</td></tr>
<tr><td class="e">Active Links</td><td class="v">1</td></tr>
<tr><td class="e">Client API version</td><td class="v">mysqlnd 8.1.27</td></tr></table>
</div>
</body>
</html>"""

    BAIT_SERVER_STATUS = """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html><head><title>Apache Status</title></head>
<body><h1>Apache Server Status for {hostname} (via 127.0.0.1)</h1>
<dl><dt>Server Version: Apache/2.4.58 (Ubuntu) OpenSSL/3.0.10 PHP/8.1.27</dt>
<dt>Server MPM: prefork</dt>
<dt>Server Built: 2023-10-26T13:44:44</dt></dl>
<dl><dt>Current Time: {current_time}</dt>
<dt>Restart Time: Monday, 10-Mar-2026 08:15:30 UTC</dt>
<dt>Parent Server Config. Generation: 1</dt>
<dt>Parent Server MPM Generation: 0</dt>
<dt>Server uptime: 14 days 5 hours 27 minutes 45 seconds</dt>
<dt>Server load: 0.08 0.03 0.01</dt>
<dt>Total accesses: 847293 - Total Traffic: 12.4 GB</dt>
<dt>CPU Usage: u1.23 s0.45 cu0 cs0 - .00137% CPU load</dt>
<dt>0.688 requests/sec - 10.6 kB/second - 15.4 kB/request</dt>
<dt>3 requests currently being processed, 7 idle workers</dt></dl>
<pre>___W___....</pre>
<table><tr><th>Srv</th><th>PID</th><th>Acc</th><th>M</th><th>CPU</th><th>SS</th><th>Conn</th><th>Client</th><th>VHost</th><th>Request</th></tr>
<tr><td>0-0</td><td>1234</td><td>0/4523/847293</td><td>W</td><td>0.45</td><td>0</td><td>0.0</td><td>{client_ip}</td><td>{hostname}:{port}</td><td>GET /server-status HTTP/1.1</td></tr>
</table></body></html>"""

    def __init__(self, config: ProtocolConfig, logger: HoneypotLogger):
        super().__init__(config, logger)
        self._server_header = config.server_header
        self._hostname = config.server_hostname

    def _http_date(self) -> str:
        """Generate RFC 7231 formatted HTTP date."""
        now = datetime.now(timezone.utc)
        days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        months = [
            "", "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
        ]
        return (
            f"{days[now.weekday()]}, {now.day:02d} {months[now.month]} "
            f"{now.year} {now.hour:02d}:{now.minute:02d}:{now.second:02d} GMT"
        )

    def _generate_etag(self, content: str) -> str:
        """Generate a realistic ETag for content."""
        h = hashlib.md5(content.encode(), usedforsecurity=False).hexdigest()[:16]
        return f'"{h}"'

    def _base_headers(self) -> dict:
        """Common headers for all responses."""
        return {
            "Date": self._http_date(),
            "Server": self._server_header,
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN",
            "X-XSS-Protection": "1; mode=block",
            "Connection": "keep-alive",
        }

    def _build_response(
        self,
        status_code: int,
        status_text: str,
        headers: dict,
        body: str = ""
    ) -> bytes:
        """Build a complete HTTP response."""
        response = f"HTTP/1.1 {status_code} {status_text}\r\n"
        for key, value in headers.items():
            response += f"{key}: {value}\r\n"
        response += "\r\n"
        if body:
            response += body
        return response.encode("utf-8")

    def _parse_request(self, raw_request: str) -> dict:
        """Parse a raw HTTP request into components."""
        result = {
            "method": "GET",
            "path": "/",
            "version": "HTTP/1.1",
            "headers": {},
            "body": "",
            "query_params": {},
        }

        try:
            parts = raw_request.split("\r\n\r\n", 1)
            header_section = parts[0]
            body = parts[1] if len(parts) > 1 else ""

            lines = header_section.split("\r\n")
            if not lines:
                return result

            # Request line
            request_line = lines[0].split(" ", 2)
            if len(request_line) >= 2:
                result["method"] = request_line[0].upper()
                full_path = request_line[1]
                if "?" in full_path:
                    path, query = full_path.split("?", 1)
                    result["path"] = path
                    result["query_params"] = dict(
                        urllib.parse.parse_qsl(query)
                    )
                else:
                    result["path"] = full_path
            if len(request_line) >= 3:
                result["version"] = request_line[2]

            # Headers
            for line in lines[1:]:
                if ": " in line:
                    key, value = line.split(": ", 1)
                    result["headers"][key] = value

            result["body"] = body

        except Exception:
            pass

        return result

    async def handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        session_id: Optional[str] = None,
    ):
        """Handle an HTTP connection (may include keep-alive)."""
        ip, port = self._get_peer_info(writer)
        conn_id = self._logger.log_connection("http", ip, port, session_id)

        try:
            # Read the full request (up to 64KB)
            raw = await self._safe_read(reader, max_bytes=65536, timeout=30.0)
            if not raw:
                return

            raw_str = raw.decode("utf-8", errors="replace")
            request = self._parse_request(raw_str)

            # Log the request
            self._logger.log_event(
                conn_id, "http_request",
                f"{request['method']} {request['path']} {request['version']}"
            )

            # Log all headers
            for hdr_name, hdr_value in request["headers"].items():
                self._logger.log_event(
                    conn_id, "http_header",
                    f"{hdr_name}: {hdr_value}"
                )

            # Log query params
            if request["query_params"]:
                self._logger.log_event(
                    conn_id, "http_query",
                    str(request["query_params"])
                )

            # Check for Authorization header
            auth_header = request["headers"].get("Authorization", "")
            if auth_header:
                self._extract_auth_credentials(conn_id, ip, auth_header)

            # Check for cookies
            cookie_header = request["headers"].get("Cookie", "")
            if cookie_header:
                self._logger.log_event(conn_id, "http_cookie", cookie_header)

            # Route based on method
            method = request["method"]
            path = request["path"]

            if method == "GET":
                response = self._handle_get(request, conn_id, ip)
            elif method == "HEAD":
                response = self._handle_head(request)
            elif method == "POST":
                response = self._handle_post(conn_id, ip, request)
            elif method == "OPTIONS":
                response = self._handle_options(request)
            elif method in ("PUT", "DELETE", "PATCH"):
                response = self._handle_method_not_allowed(request)
            else:
                response = self._handle_method_not_allowed(request)

            await self._safe_write(writer, response)

        except Exception as e:
            self._logger.log_event(conn_id, "error", str(e))
        finally:
            await self._close_writer(writer)

    def _handle_get(self, request: dict, conn_id: int = 0, ip: str = "unknown") -> bytes:
        """Handle GET request — includes bait vulnerability routes."""
        path = request["path"]
        port_num = self._config.port

        if path == "/" or path == "/index.html":
            body = self.DEFAULT_PAGE.format(
                hostname=self._hostname, port=port_num
            )
            headers = self._base_headers()
            headers.update({
                "Content-Type": "text/html; charset=UTF-8",
                "Content-Length": str(len(body.encode("utf-8"))),
                "Last-Modified": "Sat, 15 Mar 2026 10:30:00 GMT",
                "ETag": self._generate_etag(body),
                "Accept-Ranges": "bytes",
                "Vary": "Accept-Encoding",
            })
            return self._build_response(200, "OK", headers, body)

        elif path == "/favicon.ico":
            headers = self._base_headers()
            headers.update({
                "Content-Type": "image/x-icon",
                "Content-Length": "0",
            })
            return self._build_response(404, "Not Found", headers)

        # ---- BAIT VULNERABILITIES (pure string I/O) ----

        elif path == "/.env":
            # Info leak bait: fake .env with DB creds & AWS keys
            self._logger.log_event(conn_id, "bait_triggered", ".env info leak")
            body = self.BAIT_ENV_FILE.format(hostname=self._hostname)
            headers = self._base_headers()
            headers.update({
                "Content-Type": "text/plain; charset=UTF-8",
                "Content-Length": str(len(body.encode("utf-8"))),
            })
            return self._build_response(200, "OK", headers, body)

        elif path == "/.git/config":
            # Git repo leak bait
            self._logger.log_event(conn_id, "bait_triggered", ".git/config leak")
            body = self.BAIT_GIT_CONFIG.format(hostname=self._hostname)
            headers = self._base_headers()
            headers.update({
                "Content-Type": "text/plain; charset=UTF-8",
                "Content-Length": str(len(body.encode("utf-8"))),
            })
            return self._build_response(200, "OK", headers, body)

        elif path in ("/wp-config.php.bak", "/wp-config.php.old",
                       "/wp-config.php.save", "/wp-config.txt"):
            # WordPress config backup bait
            self._logger.log_event(conn_id, "bait_triggered", f"wp-config backup: {path}")
            body = self.BAIT_WP_CONFIG.format()
            headers = self._base_headers()
            headers.update({
                "Content-Type": "application/octet-stream",
                "Content-Disposition": f"attachment; filename=\"{path.lstrip('/')}\"",
                "Content-Length": str(len(body.encode("utf-8"))),
            })
            return self._build_response(200, "OK", headers, body)

        elif path in ("/wp-login.php", "/wp-admin/", "/wp-admin"):
            # WordPress login bait — serves form that captures creds on POST
            self._logger.log_event(conn_id, "bait_triggered", "wp-login page")
            body = self.BAIT_WP_LOGIN.format(hostname=self._hostname)
            headers = self._base_headers()
            headers.update({
                "Content-Type": "text/html; charset=UTF-8",
                "Content-Length": str(len(body.encode("utf-8"))),
                "X-Powered-By": "PHP/8.1.27",
            })
            return self._build_response(200, "OK", headers, body)

        elif path in ("/phpinfo.php", "/info.php", "/php_info.php"):
            # phpinfo bait — fake PHP info page with server details
            self._logger.log_event(conn_id, "bait_triggered", f"phpinfo: {path}")
            body = self.BAIT_PHPINFO.format(
                hostname=self._hostname, port=port_num, client_ip=ip
            )
            headers = self._base_headers()
            headers.update({
                "Content-Type": "text/html; charset=UTF-8",
                "Content-Length": str(len(body.encode("utf-8"))),
                "X-Powered-By": "PHP/8.1.27",
            })
            return self._build_response(200, "OK", headers, body)

        elif path.startswith("/admin") or path.startswith("/management"):
            # Admin panel bait — returns 401 with Basic auth challenge
            self._logger.log_event(conn_id, "bait_triggered", f"admin auth challenge: {path}")
            # Check if Authorization header was sent
            auth_header = request.get("headers", {}).get("Authorization", "")
            if auth_header:
                self._extract_auth_credentials(conn_id, ip, auth_header)
            body = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head><title>401 Unauthorized</title></head><body>
<h1>Unauthorized</h1>
<p>This server could not verify that you are authorized to access the document
requested. Either you supplied the wrong credentials, or your browser doesn't
understand how to supply the credentials required.</p>
<hr>
<address>Apache/2.4.58 (Ubuntu) Server at """ + self._hostname + """ Port """ + str(port_num) + """</address>
</body></html>"""
            headers = self._base_headers()
            headers.update({
                "WWW-Authenticate": f'Basic realm="Administration Panel"',
                "Content-Type": "text/html; charset=iso-8859-1",
                "Content-Length": str(len(body.encode("utf-8"))),
            })
            return self._build_response(401, "Unauthorized", headers, body)

        elif path.startswith("/server-status"):
            # Server status bait — fake Apache status page
            self._logger.log_event(conn_id, "bait_triggered", "server-status")
            now = datetime.now(timezone.utc).strftime("%A, %d-%b-%Y %H:%M:%S UTC")
            body = self.BAIT_SERVER_STATUS.format(
                hostname=self._hostname, port=port_num,
                client_ip=ip, current_time=now
            )
            headers = self._base_headers()
            headers.update({
                "Content-Type": "text/html; charset=iso-8859-1",
                "Content-Length": str(len(body.encode("utf-8"))),
            })
            return self._build_response(200, "OK", headers, body)

        # ---- END BAIT VULNERABILITIES ----

        else:
            body = self.NOT_FOUND_PAGE.format(
                path=path, hostname=self._hostname, port=port_num
            )
            headers = self._base_headers()
            headers.update({
                "Content-Type": "text/html; charset=iso-8859-1",
                "Content-Length": str(len(body.encode("utf-8"))),
            })
            return self._build_response(404, "Not Found", headers, body)

    def _handle_head(self, request: dict) -> bytes:
        """Handle HEAD request (same as GET but no body)."""
        path = request["path"]
        port_num = self._config.port

        if path == "/" or path == "/index.html":
            body = self.DEFAULT_PAGE.format(
                hostname=self._hostname, port=port_num
            )
            headers = self._base_headers()
            headers.update({
                "Content-Type": "text/html; charset=UTF-8",
                "Content-Length": str(len(body.encode("utf-8"))),
                "Last-Modified": "Sat, 15 Mar 2026 10:30:00 GMT",
                "ETag": self._generate_etag(body),
                "Accept-Ranges": "bytes",
                "Vary": "Accept-Encoding",
            })
            return self._build_response(200, "OK", headers)  # No body
        else:
            headers = self._base_headers()
            headers["Content-Type"] = "text/html; charset=iso-8859-1"
            return self._build_response(404, "Not Found", headers)

    def _handle_post(
        self, conn_id: int, ip: str, request: dict
    ) -> bytes:
        """Handle POST request (credential capture)."""
        path = request["path"]
        body = request["body"]
        port_num = self._config.port

        # Log POST body
        if body:
            self._logger.log_event(conn_id, "http_post_body", body[:2048])

            # Try to extract credentials from form data
            try:
                form_data = dict(urllib.parse.parse_qsl(body))
                username = form_data.get(
                    "username",
                    form_data.get("user", form_data.get("login", ""))
                )
                password = form_data.get(
                    "password",
                    form_data.get("pass", form_data.get("passwd", ""))
                )
                if username or password:
                    self._logger.log_credentials(
                        conn_id, "http", ip,
                        username or "(empty)",
                        password or "(empty)"
                    )
            except Exception:
                pass

        # Return 302 redirect (mimics successful login flow)
        session_id = hashlib.md5(os.urandom(16), usedforsecurity=False).hexdigest()[:26]
        headers = self._base_headers()
        headers.update({
            "Location": "/dashboard",
            "Set-Cookie": f"PHPSESSID={session_id}; path=/; HttpOnly; Secure",
            "Content-Length": "0",
        })
        return self._build_response(302, "Found", headers)

    def _handle_options(self, request: dict) -> bytes:
        """Handle OPTIONS request."""
        headers = self._base_headers()
        headers.update({
            "Allow": "GET,HEAD,POST,OPTIONS",
            "Content-Length": "0",
        })
        return self._build_response(200, "OK", headers)

    def _handle_method_not_allowed(self, request: dict) -> bytes:
        """Handle unsupported methods (PUT, DELETE, PATCH)."""
        body = self.METHOD_NOT_ALLOWED_PAGE.format(
            method=request["method"],
            path=request["path"],
            hostname=self._hostname,
            port=self._config.port,
        )
        headers = self._base_headers()
        headers.update({
            "Allow": "GET,HEAD,POST,OPTIONS",
            "Content-Type": "text/html; charset=iso-8859-1",
            "Content-Length": str(len(body.encode("utf-8"))),
        })
        return self._build_response(405, "Method Not Allowed", headers, body)

    def _extract_auth_credentials(
        self, conn_id: int, ip: str, auth_header: str
    ):
        """Extract credentials from Authorization header."""
        try:
            if auth_header.startswith("Basic "):
                import base64
                decoded = base64.b64decode(
                    auth_header[6:]
                ).decode("utf-8", errors="replace")
                if ":" in decoded:
                    username, password = decoded.split(":", 1)
                    self._logger.log_credentials(
                        conn_id, "http", ip, username, password
                    )
            else:
                self._logger.log_event(
                    conn_id, "auth_header", auth_header[:200]
                )
        except Exception:
            pass
