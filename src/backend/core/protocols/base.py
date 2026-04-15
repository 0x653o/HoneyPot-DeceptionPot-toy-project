"""
Base protocol handler ABC.
All protocol handlers extend this class.
"""

import asyncio
from abc import ABC, abstractmethod
from typing import Optional

from ..config import ProtocolConfig
from ..logger import HoneypotLogger


class BaseProtocolHandler(ABC):
    """
    Abstract base class for all honeypot protocol handlers.
    
    Each handler:
    - Listens on a specific port
    - Presents a realistic service banner
    - Captures attacker interactions (credentials, commands, payloads)
    - Logs everything via HoneypotLogger
    """

    PROTOCOL_NAME: str = "unknown"

    def __init__(self, config: ProtocolConfig, logger: HoneypotLogger):
        self._config = config
        self._logger = logger

    @property
    def port(self) -> int:
        """Port this handler listens on."""
        return self._config.port

    @property
    def protocol_name(self) -> str:
        """Protocol identifier string."""
        return self.PROTOCOL_NAME

    @abstractmethod
    async def handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        session_id: Optional[str] = None,
    ):
        """
        Handle a single connection from an attacker.
        
        Args:
            reader: asyncio StreamReader for incoming data.
            writer: asyncio StreamWriter for sending responses.
            session_id: Unique session identifier for this connection.
        """
        pass

    def _get_peer_info(self, writer: asyncio.StreamWriter) -> tuple:
        """Extract IP and port from the connection."""
        try:
            peername = writer.get_extra_info("peername")
            if peername:
                return peername[0], peername[1]
        except Exception:
            pass
        return "unknown", 0

    async def _safe_write(self, writer: asyncio.StreamWriter, data: bytes):
        """Write data to writer with error handling."""
        try:
            writer.write(data)
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            pass

    async def _safe_read(
        self,
        reader: asyncio.StreamReader,
        max_bytes: int = 4096,
        timeout: float = 10.0,
    ) -> Optional[bytes]:
        """Read data from reader with timeout and error handling."""
        try:
            data = await asyncio.wait_for(
                reader.read(max_bytes),
                timeout=timeout,
            )
            return data if data else None
        except (asyncio.TimeoutError, ConnectionResetError, 
                BrokenPipeError, ConnectionAbortedError):
            return None

    async def _safe_readline(
        self,
        reader: asyncio.StreamReader,
        timeout: float = 10.0,
    ) -> Optional[bytes]:
        """Read a line from reader with timeout and error handling."""
        try:
            data = await asyncio.wait_for(
                reader.readline(),
                timeout=timeout,
            )
            return data if data else None
        except (asyncio.TimeoutError, ConnectionResetError,
                BrokenPipeError, ConnectionAbortedError):
            return None

    async def _close_writer(self, writer: asyncio.StreamWriter):
        """Safely close the writer."""
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
