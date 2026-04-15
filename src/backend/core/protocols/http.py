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

    # Realistic Enterprise User Portal Login Page (Bait)
    DEFAULT_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Synergy Corp - Enterprise Portal</title>
<style>
  * { box-sizing: border-box; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
  body { margin: 0; padding: 0; background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); height: 100vh; display: flex; justify-content: center; align-items: center; }
  .login-container { background-color: #ffffff; width: 100%; max-width: 400px; padding: 40px; border-radius: 8px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); text-align: center; }
  .logo { font-size: 28px; font-weight: bold; color: #1e3c72; margin-bottom: 10px; }
  .subtitle { color: #666; font-size: 14px; margin-bottom: 30px; }
  .input-group { margin-bottom: 20px; text-align: left; }
  .input-group label { display: block; margin-bottom: 8px; color: #333; font-weight: 500; font-size: 14px; }
  .input-group input { width: 100%; padding: 12px; border: 1px solid #ccc; border-radius: 4px; font-size: 14px; transition: border-color 0.3s; }
  .input-group input:focus { outline: none; border-color: #1e3c72; }
  .btn-login { width: 100%; padding: 12px; background-color: #1e3c72; color: #fff; border: none; border-radius: 4px; font-size: 16px; font-weight: bold; cursor: pointer; transition: background-color 0.3s; }
  .btn-login:hover { background-color: #2a5298; }
  .links { margin-top: 20px; font-size: 13px; color: #666; }
  .links a { color: #1e3c72; text-decoration: none; }
  .links a:hover { text-decoration: underline; }
</style>
</head>
<body>
  <div class="login-container">
    <div class="logo">Synergy Corp</div>
    <div class="subtitle">Enterprise Single Sign-On</div>
    <form action="/login" method="POST">
      <div class="input-group">
        <label for="username">Employee ID / Email</label>
        <input type="text" id="username" name="username" placeholder="e.g. jdoe@synergy.corp" required>
      </div>
      <div class="input-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required>
      </div>
      <button type="submit" class="btn-login">Secure Login</button>
    </form>
    <div class="links">
      <p><a href="/?page=forgot-password.php">Forgot Password?</a></p>
      <p>Need help? Contact <a href="mailto:it-support@synergy.corp">IT Support</a></p>
      <p style="margin-top: 30px; font-size: 11px; color: #aaa;">&copy; 2024 Synergy Corporation. All rights reserved.<br>Server: {hostname}:{port}</p>
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

# Internal Management API
MGMT_API_URL=http://localhost:9090
HONEYPOT_API_KEY=hk_live_8f92bd8c734a6eef9012
"""

    BAIT_PASSWD_FILE = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:101:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:105::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
mysql:x:106:108:MySQL Server,,,:/nonexistent:/bin/false
admin:x:1000:1000:admin,,,:/home/admin:/bin/bash
postgres:x:107:109:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
redis:x:108:110:Redis Server,,,:/var/lib/redis:/usr/sbin/nologin
"""

    BAIT_SPRING_ENV = """{
  "activeProfiles": [
    "production"
  ],
  "propertySources": [
    {
      "name": "applicationConfig: [classpath:/application-production.yml]",
      "properties": {
        "spring.datasource.url": {
          "value": "jdbc:mysql://db.internal:{port}/main"
        },
        "spring.datasource.username": {
          "value": "spring_admin"
        },
        "spring.datasource.password": {
          "value": "Str0ngP@ssw0rd!2024"
        },
        "aws.secretKey": {
          "value": "AKIAIOSFODNN7EXAMPLE=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        }
      }
    }
  ]
}"""

    BAIT_EXPRESS_ERROR = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>TypeError: Cannot read properties of undefined (reading &#39;id&#39;)<br> &nbsp; &nbsp;at authMiddleware (/usr/src/app/src/middleware/auth.js:42:15)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/usr/src/app/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at next (/usr/src/app/node_modules/express/lib/router/route.js:144:13)<br> &nbsp; &nbsp;at Route.dispatch (/usr/src/app/node_modules/express/lib/router/route.js:114:3)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/usr/src/app/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at /usr/src/app/node_modules/express/lib/router/index.js:284:15<br> &nbsp; &nbsp;at Function.process_params (/usr/src/app/node_modules/express/lib/router/index.js:346:12)</pre>
</body>
</html>"""

    BAIT_PACKAGE_JSON = """{
  "name": "backend-api",
  "version": "1.0.0",
  "description": "Core API",
  "main": "src/index.js",
  "scripts": {
    "start": "node src/index.js"
  },
  "dependencies": {
    "express": "^4.17.1",
    "jsonwebtoken": "^8.5.1",
    "mongoose": "^6.0.12",
    "lodash": "^4.17.20"
  }
}"""

    BAIT_DJANGO_DEBUG = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta http-equiv="content-type" content="text/html; charset=utf-8">
  <meta name="robots" content="NONE,NOARCHIVE">
  <title>Page not found at {path}</title>
  <style type="text/css">
    html * { padding:0; margin:0; }
    body * { padding:10px 20px; }
    body * * { padding:0; }
    body { font:small sans-serif; background:#eee; color:#000; }
    body>div { border-bottom:1px solid #ddd; }
    h1 { font-weight:normal; margin-bottom:.4em; }
    h1 span { font-size:60%; color:#666; font-weight:normal; }
    table { border:none; border-collapse: collapse; width:100%; }
    td, th { vertical-align:top; padding:2px 3px; }
    th { width:12em; text-align:right; color:#666; padding-right:.5em; }
    #info { background:#f6f6f6; }
    #info ol { margin: 0.5em 4em; }
    #info ol li { font-family: monospace; }
    #summary { background: #ffc; }
    #explanation { background:#eee; border-bottom: 0px none; }
    pre.exception_value { font-family: sans-serif; color: #575757; font-size: 1.5em; margin: 10px 0 10px 0; }
  </style>
</head>
<body>
  <div id="summary">
    <h1>Page not found <span>(404)</span></h1>
    <table class="meta">
      <tr>
        <th>Request Method:</th>
        <td>GET</td>
      </tr>
      <tr>
        <th>Request URL:</th>
        <td>http://{hostname}{path}</td>
      </tr>
      <tr>
        <th>Django Version:</th>
        <td>4.2.1</td>
      </tr>
    </table>
  </div>
  <div id="info">
    <p>Using the URLconf defined in <code>config.urls</code>, Django tried these URL patterns, in this order:</p>
    <ol>
      <li>admin/</li>
      <li>api/v1/auth/</li>
      <li>api/v1/users/</li>
      <li>api/v1/billing/</li>
    </ol>
    <p>The current path, <code>{path}</code>, didn’t match any of these.</p>
  </div>
  <div id="explanation">
    <p>You’re seeing this error because you have <code>DEBUG = True</code> in your Django settings file. Change that to <code>False</code>, and Django will display a standard 404 page.</p>
  </div>
</body>
</html>"""

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
            # Read headers until \r\n\r\n
            raw = b""
            try:
                # Read chunks until we find the end of the headers
                while b"\r\n\r\n" not in raw:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=5.0)
                    if not chunk:
                        break
                    raw += chunk
                    if len(raw) > 65536: # Protection against huge headers
                        break
                        
                # If there's a Content-Length, read the body too
                raw_str = raw.decode("utf-8", errors="replace")
                headers_part = raw_str.split("\r\n\r\n")[0]
                content_length = 0
                for line in headers_part.split("\r\n"):
                    if line.lower().startswith("content-length:"):
                        try:
                            content_length = int(line.split(":")[1].strip())
                        except ValueError:
                            pass
                
                # Read remaining body bytes if needed
                body_read = len(raw) - (raw.find(b"\r\n\r\n") + 4)
                while body_read < content_length:
                    chunk = await asyncio.wait_for(reader.read(min(4096, content_length - body_read)), timeout=5.0)
                    if not chunk:
                        break
                    raw += chunk
                    body_read += len(chunk)
                    
            except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
                if not raw:
                    return

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

        elif path.startswith("/index.php") or path.startswith("/page.php"):
            # Simple Path Traversal / LFI Bait
            query = request.get("query_params", {})
            page_param = query.get("page", [""])[0] or query.get("file", [""])[0]
            
            if "../" in page_param or "..%2f" in page_param.lower() or "passwd" in page_param:
                self._logger.log_event(conn_id, "bait_triggered", f"Path Traversal (LFI): {page_param}")
                body = self.BAIT_PASSWD_FILE
                headers = self._base_headers()
                headers.update({
                    "Content-Type": "text/plain; charset=UTF-8",
                    "Content-Length": str(len(body.encode("utf-8"))),
                })
                return self._build_response(200, "OK", headers, body)
            else:
                body = self.DEFAULT_PAGE.format(hostname=self._hostname, port=port_num)
                headers = self._base_headers()
                headers.update({"Content-Type": "text/html; charset=UTF-8", "Content-Length": str(len(body.encode("utf-8")))})
                return self._build_response(200, "OK", headers, body)

        elif path.startswith("/api/v1/search"):
            # Advanced XSS Search / Reflected XSS
            query = request.get("query_params", {})
            q_param = query.get("q", [""])[0]
            
            if "<script" in q_param.lower() or "javascript:" in q_param.lower() or "onerror" in q_param.lower() or "onload" in q_param.lower():
                self._logger.log_event(conn_id, "bait_triggered", f"Reflected XSS Attempt: {q_param}")
            
            # Vulnerable API response reflecting exactly what was typed
            body = f'{{"status": "success", "results": [], "message": "No results found for \\"{q_param}\\""}}'
            headers = self._base_headers()
            headers.update({
                "Content-Type": "application/json",
                # WEAK CSP headers for XSS / XS-Search testing!
                "Content-Security-Policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval'",
                "X-XSS-Protection": "0",
                "Content-Length": str(len(body.encode("utf-8")))
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

        elif path == "/actuator/env":
            # Java Spring Boot info leak
            self._logger.log_event(conn_id, "bait_triggered", "spring boot env")
            body = self.BAIT_SPRING_ENV.format(port=port_num)
            headers = self._base_headers()
            headers.update({
                "Content-Type": "application/vnd.spring-boot.actuator.v3+json",
                "Content-Length": str(len(body.encode("utf-8"))),
            })
            return self._build_response(200, "OK", headers, body)

        elif path.startswith("/api/v1/") or path == "/api/users":
            # Node.js Express crash
            self._logger.log_event(conn_id, "bait_triggered", f"express stack trace: {path}")
            body = self.BAIT_EXPRESS_ERROR
            headers = self._base_headers()
            headers.update({
                "Content-Type": "text/html; charset=utf-8",
                "Content-Length": str(len(body.encode("utf-8"))),
                "X-Powered-By": "Express",
            })
            return self._build_response(500, "Internal Server Error", headers, body)

        elif path == "/package.json":
            # Node.js package leak
            self._logger.log_event(conn_id, "bait_triggered", "package.json leak")
            body = self.BAIT_PACKAGE_JSON
            headers = self._base_headers()
            headers.update({
                "Content-Type": "application/json",
                "Content-Length": str(len(body.encode("utf-8"))),
            })
            return self._build_response(200, "OK", headers, body)

        elif path.startswith("/django_admin") or path.startswith("/admin_dj"):
            # Python Django debug page
            self._logger.log_event(conn_id, "bait_triggered", f"django debug 404: {path}")
            body = self.BAIT_DJANGO_DEBUG.format(hostname=self._hostname, path=path)
            headers = self._base_headers()
            headers.update({
                "Content-Type": "text/html; charset=utf-8",
                "Content-Length": str(len(body.encode("utf-8"))),
            })
            return self._build_response(404, "Not Found", headers, body)

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

        if path.startswith("/api/"):
            # Attacker might be trying to use the fake MANAGEMENT API leaked in .env
            self._logger.log_event(conn_id, "bait_triggered", f"HIGH PRIORITY: Attempted management API breach on {path}")
            # Also log headers to capture if they used the fake HONEYPOT_API_KEY
            auth = request["headers"].get("X-API-Key", request["headers"].get("Authorization", ""))
            if auth:
                self._logger.log_event(conn_id, "auth_attempt", f"Token used: {auth}")

        # Simple XML External Entity (XXE) and Command Injection Bait for POST
        if body:
            self._logger.log_event(conn_id, "http_post_body", body[:2048])
            
            # XXE Check
            if "ENTITY" in body and "SYSTEM" in body:
                self._logger.log_event(conn_id, "bait_triggered", "XXE Injection Attempt")
                if "file://" in body or "/etc/passwd" in body:
                    headers = self._base_headers()
                    headers.update({"Content-Type": "application/xml"})
                    resp_body = f"<?xml version=\"1.0\"?><result>{self.BAIT_PASSWD_FILE}</result>"
                    return self._build_response(200, "OK", headers, resp_body)
                    
            # Server-Side Request Forgery Check (SSRF)
            if "url=http://" in body or "url=https://" in body or "url=file://" in body or "url=dict://" in body or "url=gopher://" in body:
                try:
                    form_data = dict(urllib.parse.parse_qsl(body))
                    url_param = form_data.get("url", form_data.get("target", ""))
                    if url_param:
                        self._logger.log_event(conn_id, "bait_triggered", f"SSRF Attempt Target: {url_param}")
                except Exception:
                    pass

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
        # Default fallback for other POSTs
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
