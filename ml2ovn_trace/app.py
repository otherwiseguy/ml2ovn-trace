from collections import namedtuple
import subprocess
import sys

import click
import openstack

# ml2ovn-trace --from server=vm1 --to server=vm2 --via router=net1-router
# pulls
#  logical_switch/inport from "from" object
#  ip.src/ip.dst from "from" object (and eth.dst if no via)
#  ip4.dest from "to" object
#  eth.dst from "via" object
#

conn = None


class ServerInterface:
    def __init__(self, query, network=None):
        self.query = query
        self._network = network
        self._instance = None
        self._ip = None
        self._mac = None
        self._floating_ip = None
        self._inport = None
        self.set_addresses()

    @property
    def datapath(self):
        return 'neutron-' + conn.search_networks(self.network)[0].id

    @property
    def instance(self):
        if not self._instance:
            matching_vms = conn.search_servers(self.query)
            if len(matching_vms) < 1:
                raise Exception('Server not found')
            elif len(matching_vms) > 1:
                raise Exception('Multiple VMs match %s' % self.query)
            self._instance = matching_vms[0]
        return self._instance

    @property
    def network(self):
        if not self._network:
            if len(self.instance.addresses) != 1:
                raise Exception('Server on multiple networks, add --network')
            self._network = next(iter(key for key in self.instance.addresses))
        return self._network

    def set_addresses(self):
        for iface in self.instance.addresses[self.network]:
            type_ = iface.get('OS-EXT-IPS:type')
            if type_ == 'fixed':
                self._ip = iface['addr']
                self._mac = iface['OS-EXT-IPS-MAC:mac_addr']
            elif type_ == 'floating':
                self._floating_ip = iface['addr']

    @property
    def ip(self):
        return self._ip

    @property
    def mac(self):
        return self._mac

    @property
    def floating_ip(self):
        return self._floating_ip

    @property
    def inport(self):
        if not self._inport:
            ports = conn.search_ports(filters={'device_id': self.instance.id})
            self._inport = ports[0].id
        return self._inport


class RouterInterface:
    def __init__(self, query, network):
        self.query = query
        self.network = conn.search_networks(network)[0]
        self.router = conn.search_routers(query)[0]
        self.interface = conn.search_ports(
            filters={'device_id': self.router.id,
                     'network_id': self.network.id})[0]
        self._ip = None
        self._mac = None

    @property
    def ip(self):
        return next(iter(ip.ip_address for ip in self.interface.fixed_ips))

    @property
    def mac(self):
        return self.interface.mac_address


def split_equals(ctx, param, value):
    if not param.required and value is None:
        return
    try:
        key, val = value.split('=', 2)
        return namedtuple('%s_opt' % param.name, ['obj', 'value'])(key, val)
    except ValueError:
        raise click.BadParameter('must be in the format object=value')


@click.command(context_settings=dict(ignore_unknown_options=True))
@click.option('--cloud', '-c', required=True, default='devstack')
@click.option('--from', '-f', 'from_', callback=split_equals, required=True,
              help='Object to fill eth.src/ip4.src from, e.g. server=vm1')
@click.option('--to', '-t', callback=split_equals, required=True,
              help='Object to fill ip4.dst and possibly eth.dst if no --via, '
                   'e.g. server=vm2')
@click.option('--via', '-V', callback=split_equals, required=False,
              help='Object to override eth.dst with, e.g. router=net1-router')
@click.option('--network', '-n', 'network', required=False,
              help='Network to limit interfaces to. If not passed, and '
                   'objects only have one, it will be used, e.g. network=net1')
@click.option('--microflow', '-m', default='',
              help='Additional microflow text to append to the one generated')
@click.option('--verbose', '-v', is_flag=True, help='Enables verbose mode')
@click.argument('ovntrace_args', nargs=-1, type=click.UNPROCESSED)
def trace(cloud, from_, to, via, network, microflow, verbose, ovntrace_args):
    global conn

    # TODO (twilson) Add configurability on confiuring connecting to te cloud
    conn = openstack.connect(cloud=cloud)
    datapath = src_mac = src_ip = dst_mac = dst_ip = None

    if from_.obj == 'server':
        server = ServerInterface(from_.value, network)
        datapath = server.datapath
        src_mac = server.mac
        src_ip = server.ip
        inport = server.inport

    if not network:
        network = server.network

    if to.obj == 'server':
        # TODO (twilson) Handle configuring network of to server
        server = ServerInterface(to.value, network)
        dst_ip = server.ip
        if not via:
            dst_mac = server.mac

    if to.obj == 'ip':
        dst_ip = to.value

    if via:
        if via.obj == 'router':
            router = RouterInterface(via.value, network)
            dst_mac = router.mac

    # need to determine inport for from object
    generated_flow = ('inport == "%s" && '
                      'eth.src == %s && '
                      'eth.dst == %s && '
                      'ip4.src == %s && '
                      'ip4.dst == %s && '
                      'ip.ttl == 64' % (inport, src_mac, dst_mac,
                                        src_ip, dst_ip))
    microflow = ' && '.join(f for f in (generated_flow, microflow) if f)
    args = ('ovn-trace', datapath, microflow) + ovntrace_args
    if verbose:
        sys.stderr.write('Calling: %s\n' % ' '.join(args))
    subprocess.run(args)


if __name__ == '__main__':
    trace()
