"""
Protocol handlers package.
"""

from .base import BaseProtocolHandler
from .ssh import SSHHandler
from .ftp import FTPHandler
from .telnet import TelnetHandler
from .smtp import SMTPHandler

PROTOCOL_MAP = {
    "ssh": SSHHandler,
    "ftp": FTPHandler,
    "telnet": TelnetHandler,
    "smtp": SMTPHandler,
}

__all__ = [
    "BaseProtocolHandler",
    "SSHHandler",
    "FTPHandler",
    "TelnetHandler",
    "SMTPHandler",
    "PROTOCOL_MAP",
]