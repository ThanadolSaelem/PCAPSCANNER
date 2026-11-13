"""Small deterministic PCAP fixtures; serialization only, never live network I/O."""
from __future__ import annotations

import socket
import struct
from pathlib import Path


def _dns_name(name: str) -> bytes:
    labels = name.rstrip(".").split(".")
    return b"".join(bytes((len(label),)) + label.encode("ascii") for label in labels) + b"\x00"


def _dns_query(transaction_id: int, name: str, *, rcode: int = 0) -> bytes:
    # Standard query with recursion desired; response bit and rcode are set for
    # the harmless NXDOMAIN sample.  No payload beyond the DNS question exists.
    flags = 0x0100 | (0x8000 if rcode else 0) | (rcode & 0xF)
    return struct.pack("!HHHHHH", transaction_id, flags, 1, 0, 0, 0) + _dns_name(name) + struct.pack("!HH", 1, 1)


def _udp_ipv4_frame(
    *,
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    payload: bytes,
) -> bytes:
    ethernet = (
        b"\x02\x00\x00\x00\x00\x01"
        + b"\x02\x00\x00\x00\x00\x02"
        + struct.pack("!H", 0x0800)
    )
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + 8 + len(payload),
        0,
        0x4000,
        64,
        17,
        0,
        socket.inet_aton(source_ip),
        socket.inet_aton(destination_ip),
    )
    udp_header = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0)
    return ethernet + ip_header + udp_header + payload


def write_synthetic_pcap(path: str | Path) -> Path:
    """Write three tiny Ethernet/IPv4/UDP DNS packets and return the path.

    The packet bytes are built in memory only for this tiny fixture.  The helper
    never opens a socket and never sends any traffic.
    """
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    packets = [
        _udp_ipv4_frame(
            source_ip="192.0.2.10",
            destination_ip="192.0.2.53",
            source_port=53000,
            destination_port=53,
            payload=_dns_query(1, "example.test"),
        ),
        _udp_ipv4_frame(
            source_ip="192.0.2.10",
            destination_ip="192.0.2.53",
            source_port=53001,
            destination_port=53,
            payload=_dns_query(2, "missing.example.test", rcode=3),
        ),
        _udp_ipv4_frame(
            source_ip="192.0.2.10",
            destination_ip="192.0.2.53",
            source_port=53002,
            destination_port=53,
            payload=_dns_query(3, "example.test"),
        ),
    ]
    with output.open("wb") as handle:
        # Classic little-endian libpcap header, followed by bounded packet records.
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1))
        for index, packet in enumerate(packets, start=1):
            handle.write(struct.pack("<IIII", 1_700_000_000 + index, index * 1000, len(packet), len(packet)))
            handle.write(packet)
    return output
