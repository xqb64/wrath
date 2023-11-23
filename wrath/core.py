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

from wrath.net import build_ipv4_datagram
from wrath.net import build_tcp_segment
from wrath.net import create_send_sock
from wrath.net import create_recv_sock
from wrath.net import unpack
from wrath.net import Flags

if t.TYPE_CHECKING:
    from wrath.cli import Port, Range
else:
    Port = Range = t.Any


async def receiver(
    event: trio.Event,
    ports: list[Port],
    ranges: list[Range],
    streams: tuple[tractor.MsgStream],
    interface: str,
    target: str,
    max_retries: int,
    workers: int = cpu_count(),
) -> t.AsyncGenerator[
    dict[int, dict[str, t.Union[int, bool]]], None
]:
    recv_sock = create_recv_sock(target)
    await recv_sock.bind((interface, 0x0800))

    event.set()

    status = {
        port: {'sent': 0, 'status': PortStatus.NOT_INSPECTED}
        for r in ranges for port in list(range(*r)) + list(ports)
    }

    # trigger the machinery
    yield [k for k in status.keys()]

    for port in status.keys():
        status[port]['sent'] += 1

    while not recv_sock.is_readable():
        await trio.sleep(0.01)

    while True:
        with trio.move_on_after(0.3) as cancel_scope:
            response = await recv_sock.recv(1024 * 16)
        if cancel_scope.cancelled_caught:
            not_inspected = [
                k for k, v in status.items()
                if v['status'] == PortStatus.NOT_INSPECTED and v['sent'] < max_retries
            ]

            if len(not_inspected) == 0:
                break

            for port in not_inspected:
                status[port]['sent'] += 1

            yield not_inspected
        else:
            src, flags = unpack(response)

            match flags:
                case Flags.SYNACK:
                    print(f"{src}: open")
                    status[src]['status'] = PortStatus.OPEN
                case Flags.RSTACK:
                    status[src]['status'] = PortStatus.CLOSED
                case _: 
                    pass
        
    closed = len({k: v for k, v in status.items() if v['status'] == PortStatus.CLOSED})
    print(f"closed ports: {closed}")

    filtered = {k: v for k, v in status.items() if v['sent'] >= max_retries and v['status'] == PortStatus.NOT_INSPECTED}
    print(f"filtered ports: {len(filtered)}")

    retried_more_than_once = len({k: v for k, v in status.items() if v['sent'] > 1})
    print(f"retried_more_than_once ports: {retried_more_than_once}")


async def inspect(semaphore: trio.Semaphore, interface: str, target: str, port: int, nap_duration: int) -> None:
    async with semaphore:
        send_sock = create_send_sock()
        ipv4_datagram = build_ipv4_datagram(interface, target)
        tcp_segment = build_tcp_segment(interface, target, port)
        await send_sock.sendto(ipv4_datagram + tcp_segment, (target, port))
        send_sock.close()
        await trio.sleep(nap_duration / 1000)


@tractor.context
async def batchworker(
    ctx: tractor.Context,
    interface: str,
    target: str,
    nap_duration: int,
) -> None:
    await ctx.started()
    semaphore = trio.Semaphore(256)
    async with ctx.open_stream() as stream:
        async with trio.open_nursery() as n:
            async for batch in stream:
                for port in batch:
                    n.start_soon(inspect, semaphore, interface, target, port, nap_duration)


async def main(
    target: str,
    interface: str,
    ports: list[Port],
    ranges: list[Range],
    nap_duration: int,
    max_retries: int,
    workers: int = cpu_count(),
) -> None:
    event = trio.Event()
    async with (
        open_actor_cluster(modules=[__name__], start_method='mp_forkserver', hard_kill=True) as portals,
        gather_contexts([
            p.open_context(
                batchworker,
                interface=interface,
                target=target,
                nap_duration=nap_duration,
            )
            for p in portals.values()
        ]) as contexts,
        gather_contexts([ctx[0].open_stream() for ctx in contexts]) as streams,
        aclosing(receiver(event, ports, ranges, streams, interface, target, max_retries)) as areceiver,
    ):
        async for update in areceiver:
            await event.wait()
            for (batch, stream) in zip(
                more_itertools.sliced(update, math.ceil(len(update) / workers)),
                itertools.cycle(streams)
            ):
                await stream.send(batch)


class PortStatus(enum.Enum):
    OPEN = enum.auto()
    CLOSED = enum.auto()
    FILTERED = enum.auto()
    NOT_INSPECTED = enum.auto()