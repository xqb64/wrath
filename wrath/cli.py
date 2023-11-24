import typing as t

import click
from click_option_group import optgroup
from click_option_group import RequiredAnyOptionGroup

import trio

from wrath.core import main


Port = int
Range = t.Tuple[Port, Port]


class PortRange(click.ParamType):
    name = "range"

    def convert(
        self,
        value: t.Any,
        param: t.Optional[click.Parameter],
        ctx: t.Optional[click.Context],
    ) -> t.Optional[Range]:
        try:
            start, end = map(int, value.split("-"))
        except ValueError:
            self.fail("You need to pass a port range (e.g. 0-1024)", param, ctx)
        else:
            if not 0 <= start <= 65534:
                self.fail("Start must be in range [0, 65534]")
            if not 1 <= end <= 65535:
                self.fail("End must be in range [1, 65535]")
            if not start < end:
                self.fail("End must be greater than start.")

            return (start, end + 1)  # inclusive


@click.command()
@click.argument("target", type=str)
@click.option(
    "--interface",
    "-i",
    type=str,
    required=True,
    help="Interface for binding the socket",
)
@click.option(
    "--batch-size", "-b", type=int, default=512, help="Batch size (for rate limiting)"
)
@click.option(
    "--spawn-delay",
    "-S",
    type=float,
    default=1,
    help="Nap duration time (in milliseconds) between two consecutive task spawns",
)
@click.option(
    "--batch-delay",
    "-B",
    type=float,
    default=1,
    help="Nap duration time (in milliseconds) between two consecutive batches",
)
@click.option(
    "--max-retries",
    "-R",
    type=int,
    default=5,
    help="Max number of retries before giving up on inspecting a port",
)
@optgroup.group("Port(s)/Port range(s)", cls=RequiredAnyOptionGroup)
@optgroup.option(
    "--port",
    "-p",
    "ports",
    type=click.IntRange(min=0, max=65535),
    multiple=True,
    help="Scan an individual port (e.g. -p 22)",
)
@optgroup.option(
    "--range",
    "-r",
    "ranges",
    type=PortRange(),
    multiple=True,
    help="Scan a port range (e.g. -r 1024-2048)",
)
def cli(
    target: str,
    interface: str,
    ports: list[Port],
    ranges: list[Range],
    spawn_delay: float,
    batch_delay: float,
    batch_size: int,
    max_retries: int,
) -> None:
    trio.run(main, target, interface, ports, ranges, spawn_delay, batch_delay, batch_size, max_retries)
