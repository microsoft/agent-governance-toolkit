# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Foreground listener ownership and truthful readiness."""

import asyncio
import signal
import socket
from contextlib import contextmanager

import click
import uvicorn

from .application import create_sidecar
from .config import Configuration, ConfigurationError


@contextmanager
def _shutdown_signals(handler):
    originals = {
        signum: signal.signal(signum, handler)
        for signum in (signal.SIGINT, signal.SIGTERM)
    }
    try:
        yield
    finally:
        for signum, original in originals.items():
            signal.signal(signum, original)


async def serve(config: Configuration, *, quiet: bool = False) -> None:
    app = create_sidecar(config)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    else:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    termination_signals = [signal.SIGTERM]
    if hasattr(signal, "SIGBREAK"):
        termination_signals.append(signal.SIGBREAK)
    prior_handlers = {signum: signal.getsignal(signum) for signum in termination_signals}
    task = asyncio.current_task()
    loop = asyncio.get_running_loop()

    def stop_startup(_signum, _frame):
        if task is not None:
            loop.call_soon_threadsafe(task.cancel)

    for signum in termination_signals:
        signal.signal(signum, stop_startup)
    try:
        await app.start()
        try:
            listener.bind((config.host, config.port))
            listener.listen(128)
            listener.setblocking(False)
        except OSError:
            raise ConfigurationError(
                "Cannot bind the configured loopback port. Stop its owner or choose an unused --port."
            ) from None

        class Server(uvicorn.Server):
            def capture_signals(self):
                # Graceful shutdown is a successful foreground exit, not a re-raised signal.
                return _shutdown_signals(self.handle_exit)

            async def startup(self, sockets=None):
                await super().startup(sockets)
                if self.started and not quiet:
                    click.echo(f"Studio ready at {config.origin} (loopback-only; save disabled)")

            async def shutdown(self, sockets=None):
                for server in self.servers:
                    server.close()
                await app.close()
                await super().shutdown(sockets)

        server = Server(uvicorn.Config(
            app, host=config.host, port=config.port, access_log=False, log_config=None,
            log_level="critical", proxy_headers=False, server_header=False,
            timeout_graceful_shutdown=config.limits.shutdown_seconds,
            h11_max_incomplete_event_size=16384, ws="none", http="h11",
        ))
        signal.signal(signal.SIGTERM, prior_handlers[signal.SIGTERM])
        if hasattr(signal, "SIGBREAK"):
            # Uvicorn's Windows console Ctrl+Break needs the same bounded shutdown path.
            signal.signal(signal.SIGBREAK, server.handle_exit)
        await server.serve(sockets=[listener])
        if not server.started:
            raise ConfigurationError("Studio ASGI startup failed; no listener is ready.")
    finally:
        for signum, handler in prior_handlers.items():
            signal.signal(signum, handler)
        listener.close()
        await app.close()


def run(config: Configuration, *, quiet: bool = False) -> None:
    try:
        asyncio.run(serve(config, quiet=quiet))
    except (KeyboardInterrupt, asyncio.CancelledError):
        return
