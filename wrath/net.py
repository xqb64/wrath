import ctypes
import functools
import random
import struct
import enum
import typing as t
from fcntl import ioctl

from attrs import define, field
from attrs.validators import instance_of
from trio import socket


TCP_SRC = 6969  # source port

SIOCGIFADDR = 0x8915

IP_HDR_LEN = 20
TCP_HDR_LEN = 20


class TcpFlag(enum.IntEnum):
    CWR = 0b10000000
    ECE = 0b01000000
    URG = 0b00100000
    ACK = 0b00010000
    PSH = 0b00001000
    RST = 0b00000100
    SYN = 0b00000010
    FIN = 0b00000001


SYNACK = TcpFlag.SYN | TcpFlag.ACK
RSTACK = TcpFlag.RST | TcpFlag.ACK


class NextLevelProtocol(enum.Enum):
    TCP = 6


@define
class TcpPacket:
    src: int = field(
        validator=[
            instance_of(int),
            lambda _instance, attribute, value: is_n_bits(attribute, value, 16),
        ],
        default=0,
    )
    dst: int = field(
        validator=[
            instance_of(int),
            lambda _instance, attribute, value: is_n_bits(attribute, value, 16),
        ],
        default=0,
    )
    seq: int = field(
        validator=[
            instance_of(int),
            lambda _instance, attribute, value: is_n_bits(attribute, value, 32),
        ],
        default=0,
    )
    ack: int = field(
        validator=[
            instance_of(int),
            lambda _instance, attribute, value: is_n_bits(attribute, value, 32),
        ],
        default=0,
    )
    data_offset: int = field(
        validator=[
            instance_of(int),
            lambda _instance, attribute, value: is_n_bits(attribute, value, 4),
        ],
        default=5,
    )
    reserved: int = field(
        validator=[
            instance_of(int),
            lambda _instance, attribute, value: is_n_bits(attribute, value, 4),
        ],
        default=0,
    )
    flags: int = field(validator=[instance_of(int)], default=0)
    window: int = field(
        validator=[
            instance_of(int),
            lambda _instance, attribute, value: is_n_bits(attribute, value, 16),
        ],
        default=0,
    )
    checksum: int = field(
        validator=[
            instance_of(int),
            lambda _instance, attribute, value: is_n_bits(attribute, value, 16),
        ],
        default=0,
    )
    urgent_ptr: int = field(
        validator=[
            instance_of(int),
            lambda _instance, attribute, value: is_n_bits(attribute, value, 16),
        ],
        default=0,
    )
    buffer: ctypes.Array[ctypes.c_char] = field(
        validator=[instance_of(ctypes.c_char * TCP_HDR_LEN)],
        default=ctypes.create_string_buffer(TCP_HDR_LEN),
    )

    def build(self) -> ctypes.Array[ctypes.c_char]:
        struct.pack_into(
            "!HHIIBBHHH",
            self.buffer,
            0,
            self.src,
            self.dst,
            self.seq,
            self.ack,
            ((self.data_offset << 4) | self.reserved),
            self.flags,
            self.window,
            self.checksum,
            self.urgent_ptr,
        )
        return self.buffer

    def set_checksum(self, pseudoheader: bytes) -> None:
        struct.pack_into(
            "!H", self.buffer, 16, inet_checksum(pseudoheader + bytes(self.buffer))
        )

    @classmethod
    def from_bytes(cls, raw_bytes: bytes) -> "TcpPacket":
        buffer = ctypes.create_string_buffer(raw_bytes, TCP_HDR_LEN)
        (
            src,
            dst,
            seq,
            ack,
            data_offset_and_reserved,
            flags,
            window,
            checksum,
            urgent_ptr,
        ) = struct.unpack("!HHIIBBHHH", buffer)
        data_offset = (data_offset_and_reserved >> 4) & 0xF
        reserved = data_offset_and_reserved & 0xF
        return TcpPacket(
            src,
            dst,
            seq,
            ack,
            data_offset,
            reserved,
            flags,
            window,
            checksum,
            urgent_ptr,
        )


@define
class Ipv4Packet:
    version: int = field(
        validator=[
            instance_of(int),
            lambda _instance, attribute, value: is_n_bits(attribute, value, 4),
        ],
        default=4,
    )
    header_length: int = field(
        validator=[
            instance_of(int),
            lambda _instance, attribute, value: is_n_bits(attribute, value, 4),
        ],
        default=5,
    )
    dscp: int = field(
        validator=[
            instance_of(int),
            lambda _instance, attribute, value: is_n_bits(attribute, value, 6),
        ],
        default=0,
    )
    ecn: int = field(
        validator=[
            instance_of(int),
            lambda _instance, attribute, value: is_n_bits(attribute, value, 2),
        ],
        default=0,
    )
    total_length: int = field(
        validator=[
            instance_of(int),
            lambda _instance, attribute, value: is_n_bits(attribute, value, 16),
        ],
        default=IP_HDR_LEN + TCP_HDR_LEN,
    )
    identification: int = field(
        validator=[
            instance_of(int),
            lambda _instance, attribute, value: is_n_bits(attribute, value, 16),
        ],
        default=0,
    )
    flags: int = field(
        validator=[
            instance_of(int),
            lambda _instance, attribute, value: is_n_bits(attribute, value, 3),
        ],
        default=0,
    )
    fragment_offset: int = field(
        validator=[
            instance_of(int),
            lambda _instance, attribute, value: is_n_bits(attribute, value, 13),
        ],
        default=0,
    )
    ttl: int = field(
        validator=[
            instance_of(int),
            lambda _instance, attribute, value: is_n_bits(attribute, value, 8),
        ],
        default=255,
    )
    next_level_protocol: NextLevelProtocol = field(
        validator=[instance_of(NextLevelProtocol)],
        default=NextLevelProtocol.TCP,
    )
    checksum: int = field(
        validator=[
            instance_of(int),
            lambda _instance, attribute, value: is_n_bits(attribute, value, 16),
        ],
        default=0,
    )
    src: str = field(validator=[instance_of(str)], default="")
    dst: str = field(validator=[instance_of(str)], default="")
    buffer: ctypes.Array[ctypes.c_char] = field(
        validator=[instance_of(ctypes.c_char * (IP_HDR_LEN))],
        default=ctypes.create_string_buffer(IP_HDR_LEN),
    )

    def build(self) -> ctypes.Array[ctypes.c_char]:
        struct.pack_into(
            "!BBHHHBBH4s4s",
            self.buffer,
            0,
            ((self.version << 4) | self.header_length),
            ((self.dscp << 6) | self.ecn),
            self.total_length,
            self.identification,
            ((self.flags << 13) | self.fragment_offset),
            self.ttl,
            self.next_level_protocol.value,
            self.checksum,
            socket.inet_aton(self.src),
            socket.inet_aton(self.dst),
        )
        return self.buffer

    def set_checksum(self, checksum: int) -> None:
        struct.pack_into("!H", self.buffer, 10, inet_checksum(bytes(self.buffer)))


def is_n_bits(attribute: t.Any, value: int, n: int) -> None:
    if value.bit_length() > n:
        raise ValueError(f"'{attribute.name}' has to be a {n}-bit number")


@functools.cache
def get_iface_ip(interface: str) -> str:
    """
    Returns the IP address of the interface.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip_addr = socket.inet_ntoa(
        ioctl(
            sock.fileno(),
            SIOCGIFADDR,
            struct.pack("256s", bytes(interface[:15], "UTF-8")),
        )[20:24]
    )
    sock.close()
    return ip_addr


def create_send_sock() -> socket.SocketType:
    """
    Creates a raw AF_INET sending socket requiring an accompanying IP header.
    """
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return send_sock


def create_recv_sock() -> socket.SocketType:
    """
    Creates a raw AF_INET receiving socket that speaks TCP.
    """
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    return recv_sock


def inet_checksum(header: bytes) -> int:
    checksum = 0
    for idx in range(0, len(header), 2):
        checksum += (header[idx] << 8) | header[idx + 1]
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF
    return checksum


@functools.cache
def build_ipv4_datagram(interface: str, target: str) -> bytes:
    """
    Builds an IPv4 datagram destined to a particular address.
    """
    ip_src = get_iface_ip(interface)

    ipv4_packet = Ipv4Packet(src=ip_src, dst=target)

    buffer = ipv4_packet.build()

    ipv4_packet.set_checksum(inet_checksum(bytes(buffer)))

    return bytes(ipv4_packet.buffer)


def build_tcp_segment(interface: str, target: str, port: int) -> bytes:
    """
    Builds a TCP segment destined to a particular port.
    """
    ip_src = get_iface_ip(interface)

    tcp_packet = TcpPacket(
        src=TCP_SRC,
        dst=port,
        seq=random.randint(0, 2**32 - 1),
        flags=TcpFlag.SYN,
        window=0x7110,
    )

    buffer = tcp_packet.build()

    tcp_pseudo_header = build_tcp_pseudo_hdr(ip_src, target, len(buffer))
    tcp_packet.set_checksum(tcp_pseudo_header)

    return bytes(tcp_packet.buffer)


@functools.cache
def build_tcp_pseudo_hdr(ip_src: str, ip_dest: str, length: int) -> bytes:
    return struct.pack(
        "!4s4sHHH",
        socket.inet_aton(ip_src),
        socket.inet_aton(ip_dest),
        NextLevelProtocol.TCP.value,
        length,
        0,
    )


async def dns_lookup(host: str) -> str:
    info = await socket.getaddrinfo(host, None)
    ip, *_ = info[0][-1]
    return ip
