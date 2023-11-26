![wrath](wrath.png)

<h1 align="center">wrath</h1>

A networking tool optimized for scanning sizable port ranges as quickly as possible.

## How it works

For tackling this problem, `wrath` gathers all the ports together and slices the resulting set into optimally-sized batches. It then spawns several worker processes (proportionally to the count of CPU cores) and dispatches the slices. Consequently, this maximizes CPU utilization and uniformly distributes the load across the CPU cores. The worker processes are actors that communicate between themselves and the parent process via message passing.  Everything inside an actor happens asynchronously, unleashing the full power of parallelism united with asynchrony.

The scanning technique used is the so-called "stealth" (or "half-open") scanning, i.e., sending TCP packets with the SYN bit set and either waiting for SYN/ACK or RST/ACK. Upon receiving the response, the kernel sends back another TCP packet with the RST bit set, effectively closing the connection in the middle of the handshake.

## Results

In a lab environment with four cores and a direct 15m Category 6e link to the target router, `wrath` managed to inspect 64K ports in under 10 seconds.

```sh
alex@smartalex-pc:~/Repositories/wrath$ time sudo $PYEXE -m wrath 192.168.1.1 -i enp5s0 -r 0-65535 --spawn-delay 0.001 --batch-delay 1 --batch-size 512
53: open
80: open
515: open
18017: open
3394: open
5473: open
39380: open
9100: open
3838: open
closed ports: 65527
filtered ports: 0
retried_more_than_once ports: 13421

real	0m9,399s
user	0m0,008s
sys	0m0,001s
```

## FAQ

**Q**: Was the pun in the name...?

**A**: Yes, the pun in the name was intended.

## Installing

```
git clone https://github.com/xqb64/wrath
cd wrath
python3 -m venv env
source env/bin/activate
pip install .
export PYEXE=$(poetry env info -p)/bin/python
```

Now you can run the program, e.g.:

```
sudo $PYEXE -m wrath 192.168.1.1 -i enp5s0 -r 0-65535 --spawn-delay 0.001 --batch-delay 1 --batch-size 512
```

## Contributing

Contributions are very welcome, in particular, suggestions (and patches) as for how to make the whole system faster. Make sure you copy/paste the pre-commit hook into `.git/hooks`.

## Status

Usable, but still needs a polish.
