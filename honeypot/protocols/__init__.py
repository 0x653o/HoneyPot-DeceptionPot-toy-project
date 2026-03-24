"""
Protocol handlers package.
"""

from .base import BaseProtocolHandler
from .ssh import SSHHandler
from .http import HTTPHandler
from .ftp import FTPHandler
from .telnet import TelnetHandler
from .smtp import SMTPHandler

PROTOCOL_MAP = {
    "ssh": SSHHandler,
    "http": HTTPHandler,
    "ftp": FTPHandler,
    "telnet": TelnetHandler,
    "smtp": SMTPHandler,
}

__all__ = [
    "BaseProtocolHandler",
    "SSHHandler",
    "HTTPHandler",
    "FTPHandler",
    "TelnetHandler",
    "SMTPHandler",
    "PROTOCOL_MAP",
]
