<h1 align="center">wrath</h1>

This project, a TCP SYN reconnaissance tool, marks my intial venture into the realm of computer network programming. The idea was not to create a battle-tested `nmap` successor, but to have fun exploring computer networks more closely and see how far I could push Python performance-wise. I learned a ton about hands-on networking and putting it together brought me a lot of pleasure, so I'd say the target has been met. ;-)

## How it works

For tackling this problem, `wrath` gathers all the ports together and slices the resulting set into optimally-sized batches. It then spawns several worker processes (proportionally to the count of CPU cores) and dispatches the slices to the worker processes. Consequently, this maximizes CPU utilization and uniformly distributes the load across the CPU cores. The worker processes are actors that communicate with the parent process via message passing. Everything inside a process happens asynchronously, unleashing the full power of parallelism united with asynchrony.

The technique used, known as "stealth" (or "half-open") scanning, involves sending TCP packets with the `SYN` bit set. There are three pathways from here:

- If the target responds with `SYNACK`, it means that the port is open.
- If the target responds with `RSTACK`, the port is considered closed.
- If the target machine does not respond at all, `tsunami` will retry at most `--max-retries` times before reporting the port as filtered.

## Let's talk numbers

In a lab environment on a machine with four cores and a direct 15m Category 6e link to the target router (`Asus RT-AC58U`, firmware `3.0.0.4.382_52134`), `wrath` managed to inspect 64K ports in under 7 seconds.

```sh
(env) alex@smartalex-pc:~/Repositories/wrath$ time sudo $PYEXE -m wrath 192.168.1.1 -i enp5s0 -r 0-65535 --spawn-delay 0 --batch-delay 0.01 --batch-size 32
53: open
80: open
515: open
34091: open
18017: open
3394: open
9100: open
3838: open
5473: open
closed ports: 65527
filtered ports: 0
retried_more_than_once ports: 26288

real	0m6,888s
user	0m0,000s
sys	0m0,009s
```

## Installing

```
git clone https://github.com/xqb64/wrath
cd wrath
python3 -m venv env
source env/bin/activate
pip install .
export PYEXE=$(which python)
```

Now you can run the program, e.g.:

```
sudo $PYEXE -m wrath 192.168.1.1 -i enp5s0 -r 0-65535 --spawn-delay 0 --batch-delay 0.01 --batch-size 32
```

## Usage

```
Usage: python -m wrath [OPTIONS] TARGET

Options:
  -i, --interface TEXT            Interface for binding the
                                  socket  [required]
  -b, --batch-size INTEGER        Batch size (for rate
                                  limiting)
  -S, --spawn-delay FLOAT         Nap duration time (in
                                  milliseconds) between two
                                  consecutive task spawns
  -B, --batch-delay FLOAT         Nap duration time (in
                                  milliseconds) between two
                                  consecutive batches
  -R, --max-retries INTEGER       Max number of retries
                                  before giving up on
                                  inspecting a port
  Port(s)/Port range(s): [required_any]
    -p, --port INTEGER RANGE      Scan an individual port
                                  (e.g. -p 22)
                                  [0<=x<=65535]
    -r, --range RANGE             Scan a port range (e.g.
                                  -r 1024-2048)
  --help                          Show this message and
                                  exit.
```

## FAQ

**Q**: Was the pun in the name...?

**A**: Yes, the pun in the name was intended.

## See also

[tsunami](https://github.com/xqb64/tsunami) - My second and more performant attempt, written in Rust

## Contributing

Contributions are very welcome, in particular, suggestions (and patches) as for how to make the whole system faster. Make sure you copy/paste the pre-commit hook into `.git/hooks`.

## References

- https://datatracker.ietf.org/doc/html/rfc791
- https://datatracker.ietf.org/doc/html/rfc9293

## Licensing

Licensed under the [MIT License](https://opensource.org/licenses/MIT). For details, see [LICENSE](https://github.com/xqb64/wrath/blob/master/LICENSE).