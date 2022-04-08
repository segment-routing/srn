# Software Resolved Networks

Software Resolved Networks (SRN) are a variant of the SDN architecture.
An SRN is a network that is managed by a logically centralized controller.
The name SRN originates from the fact that the architecture co-locates
its controller with a DNS resolver and uses extensions of the DNS protocol
to interact with endhosts.

## Getting started

### Prerequistes

Two libraries must be installed:
- [jansson](https://github.com/akheron/jansson)
- [zlog](https://hardysimpson.github.io/zlog/)

Several other software are required:
- DNS server like [bind](https://www.isc.org/downloads/bind/)
- [ovsdb](https://github.com/openvswitch/ovs)

A modified version of [quagga](http://www.nongnu.org/quagga/index.html) is used and therefore, a quagga user must be created.

### Compiling

Simply running `make` will compile the code. Note that [jansson](https://github.com/akheron/jansson/) and [zlog](https://hardysimpson.github.io/zlog/) libraries must be installed and that this repository [submodules](https://git-scm.com/book/nl/v1/Git-tools-Submodules) must be cloned.

### Deployment of SRN

#### Quick emulation

To quickly emulate an SRN, you can use the library [srnmininet](https://github.com/segment-routing/srnmininet). More information can be found in this repository.

#### Manual setup

If you wish to deploy it in a real environment, you have to perform the following steps.

1. Get the OVSDB server ready by running it on the controller node.
```
ovsdb-tool create sr.ovschema SR_test
ovsdb-server SR_test --remote=ptcp:6640:[::1] --remote=ptcp:6640:[<global-ipv6-address>]
```

2. Fill the OVSDB database with routers and links.
```
$ ovsdb-client transact tcp:[::1]:6640 "[\"SR_test\",{\"row\":${row},\"table\":\"NameIdMapping\",\"op\":\"insert\"}]"

with row being one-line string representing a JSON object of the form:
{
	"routerName": "RouterA",  # The name of the router
	"routerId": "0.0.0.1",    # The OSPFv3 Router ID (useful to map link/router loss to the router line in OVSDB)
	"addr": "fd:1234::1",     # The address on the loopback interface of this router
	"prefix": "fd:1234:24::/64;fd:1234:10::/64",  # The list of sub-networks prefixes directly connected to the router
	"pbsid": "fd:1234::/64"   # The range of IP addresses that can be used as Binding SID for this router. You will typically choose the a /64 prefix of a loopback address.
}

$ ovsdb-client transact tcp:[::1]:6640 "[\"SR_test\",{\"row\":${row},\"table\":\"AvailableLink\",\"op\":\"insert\"}]"

with row being one-line string representing a JSON object of the form:
{
	"name1": "RouterA",        # The name of an endpoint of the link
	"name2": "RouterB",        # The name of the other endpoint
	"addr1": "fd:1234:24::a",  # The address of RouterA
	"addr2": "fd:1234:24::b",  # The address of RouterB
	"routerId1":               # The OSPFv3 Router ID of RouterA
	"routerId2":               # The OSPFv3 Router ID of RouterB
	"metric": 1                # The IGP metric of the link
	"bw": 100000               # Bandwidth (in Mbits)
	"ava_bw": 100000           # Available bandwidth (in Mbits)
	"delay": 5                 # Delay (in ms)
}
```

3. Run your favorite DNS server on one of the nodes.

4. Run the controller with the command below. Performance will be better if it is located near the OVSDB server. The configuration file options are documented in *sr-ctrl/README.md*.
```
sr-ctrl/sr-ctrl <sr-ctrl_configfile>
```

5. Run the DNS proxy on the controller node. Performance will be better if it is located near the OVSDB server and the DNS server. The configuration file options are documented in *sr-dnsproxy/README.md*.
```
sr-dnsproxy/sr-dnsproxy <sr-dnsproxy_configfile>
```

6. Run the sr-routed deamons on each access router. The configuration file and its parameters are documented in *sr-routed/README.md*.
```
sr-routed/sr-routed <sr-routed_configfile>
```

7. Run generated *sr-nsd/zebra* and *sr-nsd/ospf6d* on one of the routers. The following option must be activated in ospf6d Quagga deamon configuration. Performance will be better if the selected router is located nea the OVSDB server.
```
router ospf6
  ovsdb_adv tcp <ovsdb-server-ip> 6640 SR_test
```

8. Run example applications like *sr-client/client* or *sr-testdns/sr-testdns* by specifying the address of the *sr-dnsproxy* as the DNS resolver

