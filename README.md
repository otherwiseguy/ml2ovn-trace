ml2ovn-trace
============

This is a simple wrapper around ovn-trace that will fill in datapath, inport,
eth.src, ip.src, eth.dst, and ip.dst based on values pulled from openstack
objects.

Usage
-----
```
$ ml2ovn-trace --help
Usage: ml2ovn-trace [OPTIONS]

Options:
  -c, --cloud TEXT    [required]
  -f, --from TEXT     Object to fill eth.src/ip4.src from, e.g. server=vm1
                      [required]

  -t, --to TEXT       Object to fill ip4.dst and possibly eth.dst if no --via,
                      e.g. server=vm2  [required]

  -V, --via TEXT      Object to override eth.dst with, e.g. router=net1-router
  -n, --network TEXT  Network to limit interfaces to. If not passed, and
                      objects only have one, it will be used, e.g.
                      network=net1

  --help              Show this message and exit.
```


Example
-------
If vm1 and vm2 only have one network interface and you want to trace between them:

`$ ml2ovn-trace --from server=vm1 --to server=vm2`

Or if you want to limit to a specific network:

`$ ml2ovn-trace --network net1 --from server=vm1 --to server=vm2`

Or if you want to go from one vm1 to the floating IP of vm2 via vm1's router

`$ ml2ovn-trace --network net1 --from server=vm1 --to ip=172.18.1.7 --via router=net1-router`
