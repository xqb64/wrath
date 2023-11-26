import enum
import itertools
import math
import typing as t
from multiprocessing import cpu_count
import more_itertools
import trio
import tractor
from tractor import open_actor_cluster
from tractor.trionics import gather_contexts
from async_generator import aclosing

from wrath.net import (
    IP_HDR_LEN,
    RSTACK,
    SYNACK,
    TCP_HDR_LEN,
    TcpPacket,
    build_ipv4_datagram,
    dns_lookup,
)
from wrath.net import build_tcp_segment
from wrath.net import create_send_sock
from wrath.net import create_recv_sock
from wrath.net import TCP_SRC


if t.TYPE_CHECKING:
    from wrath.cli import Port, Range
else:
    Port = Range = t.Any


class PortStatus(enum.Enum):
    OPEN = enum.auto()
    CLOSED = enum.auto()
    FILTERED = enum.auto()
    NOT_INSPECTED = enum.auto()


class StatusInfo(t.TypedDict):
    sent: int
    status: PortStatus


async def receiver(
    event: trio.Event,
    ports: list[Port],
    ranges: list[Range],
    max_retries: int,
) -> t.AsyncGenerator[list[int], None]:
    recv_sock = create_recv_sock()
    await recv_sock.bind(("0.0.0.0", TCP_SRC))

    event.set()

    status: dict[int, StatusInfo] = {
        port: {"sent": 0, "status": PortStatus.NOT_INSPECTED}
        for r in ranges
        for port in list(range(*r))
    }

    for port in ports:
        status[port] = {"sent": 0, "status": PortStatus.NOT_INSPECTED}

    # trigger the machinery
    yield [k for k in status.keys()]

    for port in status.keys():
        status[port]["sent"] += 1

    while not recv_sock.is_readable():
        await trio.sleep(0.01)

    while True:
        with trio.move_on_after(0.3) as cancel_scope:
            response = await recv_sock.recv(1024)
        if cancel_scope.cancelled_caught:
            not_inspected = [
                k
                for k, v in status.items()
                if v["status"] == PortStatus.NOT_INSPECTED and v["sent"] < max_retries
            ]

            if len(not_inspected) == 0:
                break

            if recv_sock.is_readable():
                continue

            yield not_inspected

            for port in not_inspected:
                status[port]["sent"] += 1

            while not recv_sock.is_readable():
                await trio.sleep(0.01)
        else:
            tcp_packet = TcpPacket.from_bytes(
                response[IP_HDR_LEN : IP_HDR_LEN + TCP_HDR_LEN]
            )

            src = tcp_packet.src
            flags = tcp_packet.flags

            try:
                if status[src]["status"] != PortStatus.NOT_INSPECTED:
                    continue
            except KeyError:
                # we did not ask for this port
                continue

            match flags:
                case f if f == SYNACK:
                    print(f"{src}: open")
                    status[src]["status"] = PortStatus.OPEN
                case f if f == RSTACK:
                    status[src]["status"] = PortStatus.CLOSED
                case _:
                    pass

    closed = len({k: v for k, v in status.items() if v["status"] == PortStatus.CLOSED})
    print(f"closed ports: {closed}")

    filtered = {
        k: v
        for k, v in status.items()
        if v["sent"] >= max_retries and v["status"] == PortStatus.NOT_INSPECTED
    }
    print(f"filtered ports: {len(filtered)}")

    retried_more_than_once = len({k: v for k, v in status.items() if v["sent"] > 1})
    print(f"retried_more_than_once ports: {retried_more_than_once}")


async def inspect(
    limiter: trio.CapacityLimiter, interface: str, target: str, port: int
) -> None:
    async with limiter:
        send_sock = create_send_sock()
        ipv4_datagram = build_ipv4_datagram(interface, target)
        tcp_segment = build_tcp_segment(interface, target, port)
        await send_sock.sendto(ipv4_datagram + tcp_segment, (target, port))
        send_sock.close()


@tractor.context
async def batchworker(
    ctx: tractor.Context,
    interface: str,
    target: str,
    batch_size: int,
    spawn_delay: float,
    batch_delay: float,
) -> None:
    await ctx.started()
    limiter = trio.CapacityLimiter(1024)
    async with ctx.open_stream() as stream:
        async with trio.open_nursery() as n:
            async for batch in stream:
                for microbatch in more_itertools.sliced(batch, batch_size):
                    for port in microbatch:
                        n.start_soon(inspect, limiter, interface, target, port)
                        await trio.sleep(spawn_delay / 1000)
                    await trio.sleep(batch_delay / 1000)


async def main(
    target: str,
    interface: str,
    ports: list[Port],
    ranges: list[Range],
    spawn_delay: float,
    batch_delay: float,
    batch_size: int,
    max_retries: int,
    workers: int = cpu_count(),
) -> None:
    event = trio.Event()
    target = await dns_lookup(target)
    async with (
        open_actor_cluster(
            modules=[__name__], start_method="mp_forkserver", hard_kill=True
        ) as portals,
        gather_contexts(
            [
                p.open_context(
                    batchworker,
                    interface=interface,
                    target=target,
                    batch_size=batch_size,
                    spawn_delay=spawn_delay,
                    batch_delay=batch_delay,
                )
                for p in portals.values()
            ]
        ) as contexts,
        gather_contexts([ctx[0].open_stream() for ctx in contexts]) as streams,
        aclosing(receiver(event, ports, ranges, max_retries)) as areceiver,
    ):
        async for update in areceiver:
            await event.wait()
            for batch, stream in zip(
                more_itertools.sliced(update, math.ceil(len(update) / workers)),
                itertools.cycle(streams),
            ):
                await stream.send(batch)
