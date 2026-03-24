"""
Honeypot Core Server

Async TCP listener that:
1. Loads config and initializes all components
2. Starts a listener on each enabled protocol port  
3. Accepts connections and dispatches to protocol handlers
4. Applies rate limiting per-IP
5. Wraps each connection in a sandbox (nsjail or timeout fallback)
6. Handles graceful shutdown
"""

import asyncio
import signal
import logging
import sys
from typing import Dict, Optional

from .config import load_config, HoneypotConfig
from .logger import HoneypotLogger
from .sandbox import NsjailSandbox
from .utils import RateLimiter, generate_session_id
from .protocols import PROTOCOL_MAP, BaseProtocolHandler

logger = logging.getLogger("honeypot.core")


class HoneypotServer:
    """
    Main honeypot server that orchestrates all protocol listeners,
    rate limiting, sandboxing, and logging.
    """

    def __init__(self, config: HoneypotConfig):
        self._config = config
        self._hp_logger = HoneypotLogger(config.logging)
        self._sandbox = NsjailSandbox(config.sandbox)
        self._rate_limiter = RateLimiter(config.rate_limit)
        self._servers: list = []
        self._handlers: Dict[int, BaseProtocolHandler] = {}
        self._running = False
        self._active_connections = 0

    def _initialize_handlers(self):
        """Create protocol handler instances for all enabled protocols."""
        enabled = self._config.get_enabled_protocols()

        for name, proto_config in enabled.items():
            handler_class = PROTOCOL_MAP.get(name)
            if handler_class is None:
                self._hp_logger.log_system(
                    "warning",
                    f"Unknown protocol '{name}' in config, skipping."
                )
                continue

            handler = handler_class(proto_config, self._hp_logger)
            self._handlers[proto_config.port] = handler
            self._hp_logger.log_system(
                "info",
                f"Registered {name.upper()} handler on port {proto_config.port}"
            )

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        handler: BaseProtocolHandler,
    ):
        """Handle a single incoming connection with rate limiting and sandboxing."""
        peername = writer.get_extra_info("peername")
        ip = peername[0] if peername else "unknown"
        port = peername[1] if peername else 0

        # Rate limit check
        if not self._rate_limiter.is_allowed(ip):
            self._hp_logger.log_system(
                "warning",
                f"Rate limited: {ip} on {handler.protocol_name}"
            )
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return

        self._active_connections += 1
        session_id = generate_session_id()

        try:
            # Run handler inside sandbox (with timeout)
            await self._sandbox.run_sandboxed(
                handler.handle,
                reader,
                writer,
                session_id=session_id,
            )
        except Exception as e:
            self._hp_logger.log_system(
                "error",
                f"Handler error for {ip} on {handler.protocol_name}: {e}"
            )
        finally:
            self._active_connections -= 1
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self):
        """Start all protocol listeners."""
        self._initialize_handlers()

        if not self._handlers:
            self._hp_logger.log_system(
                "error",
                "No protocol handlers registered. Check config.yaml."
            )
            return

        self._running = True

        for port, handler in self._handlers.items():
            try:
                server = await asyncio.start_server(
                    lambda r, w, h=handler: self._handle_connection(r, w, h),
                    host="0.0.0.0",
                    port=port,
                    reuse_address=True,
                )
                self._servers.append(server)
                self._hp_logger.log_system(
                    "info",
                    f"Listening on 0.0.0.0:{port} "
                    f"({handler.protocol_name.upper()})"
                )
            except PermissionError:
                self._hp_logger.log_system(
                    "error",
                    f"Permission denied binding to port {port}. "
                    f"Try running with elevated privileges or use ports > 1024."
                )
            except OSError as e:
                self._hp_logger.log_system(
                    "error",
                    f"Cannot bind to port {port}: {e}"
                )

        if not self._servers:
            self._hp_logger.log_system(
                "error",
                "Failed to start any listeners."
            )
            return

        self._hp_logger.log_system("info", "=" * 50)
        self._hp_logger.log_system("info", " Honeypot is ACTIVE")
        self._hp_logger.log_system("info", f" Listening on {len(self._servers)} ports")
        self._hp_logger.log_system("info", f" Sandbox: {'nsjail' if self._sandbox.is_available else 'timeout-only'}")
        self._hp_logger.log_system("info", f" Rate limit: {self._config.rate_limit.max_connections}/{'enabled' if self._config.rate_limit.enabled else 'disabled'}")
        self._hp_logger.log_system("info", "=" * 50)

        # Setup signal handlers for graceful shutdown
        loop = asyncio.get_running_loop()
        if sys.platform != "win32":
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, lambda: asyncio.create_task(self.shutdown()))

        # Keep running until shutdown
        try:
            await asyncio.gather(
                *(server.serve_forever() for server in self._servers)
            )
        except asyncio.CancelledError:
            pass

    async def shutdown(self):
        """Gracefully shut down all listeners."""
        self._hp_logger.log_system("info", "Shutting down honeypot...")
        self._running = False

        for server in self._servers:
            server.close()

        for server in self._servers:
            await server.wait_closed()

        self._hp_logger.log_system(
            "info",
            f"Shutdown complete. {self._active_connections} connections were active."
        )

        # Cancel all running tasks
        tasks = [
            t for t in asyncio.all_tasks()
            if t is not asyncio.current_task()
        ]
        for task in tasks:
            task.cancel()


async def run_server(config_path: str = "config.yaml"):
    """Main entry point to run the honeypot server."""
    config = load_config(config_path)
    server = HoneypotServer(config)

    try:
        await server.start()
    except KeyboardInterrupt:
        await server.shutdown()
