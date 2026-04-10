"""
HTTPS Protocol Handler
Inherits from HTTPHandler but wraps the socket in an intentionally 
vulnerable SSL/TLS context to attract legacy cryptography scanners.
"""

import ssl
import subprocess
from pathlib import Path

from .http import HTTPHandler

class HTTPSHandler(HTTPHandler):
    """Fake HTTPS Server acting as an SSL/TLS Vuln Bait."""

    PROTOCOL_NAME = "https"

    def get_ssl_context(self) -> ssl.SSLContext:
        """Returns a deliberately insecure SSL context."""
        cert_path = Path("cert.pem")
        key_path = Path("key.pem")

        # Auto-generate self-signed cert if missing
        if not cert_path.exists() or not key_path.exists():
            self._logger.log_system("info", "Auto-generating self-signed certificate for insecure HTTPS honeypot...")
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(key_path), "-out", str(cert_path),
                "-days", "3650", "-nodes",
                "-subj", "/C=US/ST=State/L=City/O=Vulnerable Inc/CN=vulnerable.local"
            ], check=False, capture_output=True)

        # Create basic SSL context
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

        try:
            # Load the mocked certificate
            if cert_path.exists():
                context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
            
            # Make it deliberately INSECURE (Legacy TLS Bait)
            # Disable TLS 1.3 and 1.2
            context.options |= getattr(ssl, "OP_NO_TLSv1_3", 0)
            context.options |= getattr(ssl, "OP_NO_TLSv1_2", 0)
            # Allow all weak ciphers
            context.set_ciphers('ALL:@SECLEVEL=0')
        except Exception as e:
            self._logger.log_system("warning", f"Failed to downgrade HTTPS security: {e}")

        return context
