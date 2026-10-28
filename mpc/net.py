"""Tiny length-prefixed JSON framing over asyncio streams.

Each message is a 4-byte big-endian length followed by that many bytes of
compact, key-sorted JSON. Plain TCP: no encryption or authentication, so this
models the *private channels* assumed by the protocol. A real deployment would
wrap the connections in TLS (ideally mutually authenticated).
"""

from __future__ import annotations

import asyncio
import json
import struct

MAX_MESSAGE = 1 << 20  # reject frames over 1 MiB


def encode_msg(msg: dict) -> bytes:
    """Serialize a message dict to its exact on-the-wire payload (no header)."""
    return json.dumps(msg, separators=(",", ":"), sort_keys=True).encode()


async def send_msg(writer: asyncio.StreamWriter, msg: dict) -> bytes:
    """Send one framed message; returns the payload bytes that were sent."""
    raw = encode_msg(msg)
    writer.write(struct.pack(">I", len(raw)) + raw)
    await writer.drain()
    return raw


async def read_msg(reader: asyncio.StreamReader) -> tuple[dict, bytes]:
    """Read one framed message; returns (parsed dict, raw payload bytes).

    Raises asyncio.IncompleteReadError on a closed/truncated stream and
    ValueError on an oversized frame or invalid JSON.
    """
    (length,) = struct.unpack(">I", await reader.readexactly(4))
    if length > MAX_MESSAGE:
        raise ValueError(f"frame of {length} bytes exceeds limit")
    raw = await reader.readexactly(length)
    msg = json.loads(raw)
    if not isinstance(msg, dict):
        raise ValueError("message must be a JSON object")
    return msg, raw


async def connect_with_retry(host: str, port: int, timeout: float):
    """Open a connection, retrying while the peer's server is still starting."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        try:
            return await asyncio.open_connection(host, port)
        except OSError:
            if loop.time() >= deadline:
                raise
            await asyncio.sleep(0.05)
