ml2ovn-trace
============

This is a simple wrapper around ovn-trace that will fill in datapath, inport,
eth.src, ip.src, eth.dst, and ip.dst based on values pulled from openstack
objects.

Usage
-----
```
Usage: ml2ovn-trace [OPTIONS] [OVNTRACE_ARGS]...

Options:
  -c, --cloud TEXT                Cloud from clouds.yaml to connect to
  -n, --net TEXT                  Network to limit interfaces lookups to
  --from-net TEXT                 Network to limit src interface lookups to
  --to-net TEXT                   Network to limit dst interface lookups to
  -f, --from OBJECT=VALUE         Fill eth-src/ip-src from the same object,
                                  e.g. server=vm1

  --eth-src OBJECT=VALUE          Object from which to fill eth.src
                                  [required]

  --ip-src OBJECT=VALUE           Object from which to fill ip.src
                                  [required]

  -t, --to OBJECT=VALUE           Fill eth-dst/ip-dst from the same object,
                                  e.g. server=vm2

  -v, --eth-dst, --via OBJECT=VALUE
                                  Object from which to fill eth.dst
                                  [required]

  --ip-dst OBJECT=VALUE           Object from which to fill ip.dst
                                  [required]

  -m, --microflow TEXT            Additional microflow text to append to the
                                  one generated

  -v, --verbose                   Enables verbose mode
  --dry-run                       Print ovn-trace output, but don't run it
  --help                          Show this message and exit.
```


Example
-------
If vm1 and vm2 only have one network interface and you want to trace between them:

`# ml2ovn-trace --from server=vm1 --to server=vm2`

Or if you want to limit to a specific network:

`# ml2ovn-trace --network net1 --from server=vm1 --to server=vm2`

Or if you want to go from one vm1 to the floating IP of vm2 via vm1's router:

`# ml2ovn-trace --network net1 --from server=vm1 --to ip=172.18.1.7 --via router=net1-router`

To add to the generated microflow, use -m. For example, for SSH:

`# ml2ovn-trace --network net1 --from server=vm1 --to server=vm2 -m "tcp.dst==22"`

To pass arbitrary (non microflow) arguments to ovn-trace, place them after '--':

`# ml2ovn-trace --network net1 --from server=vm1 --to server=vm2 -- --summary`
