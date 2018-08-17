# Software Resolved Networks

Software Resolved Networks (SRN) are a variant of the SDN architecture.
An SRN is a network that is managed by a logically centralized controller.
The name SRN originates from the fact that the architecture co-locates
its controller with a DNS resolver and uses extensions of the DNS protocol
to interact with endhosts.

## Getting started

### Prerequistes

One library must be installed:
- (jansson)[http://www.digip.org/jansson/]

Several other software are required:
- DNS server like (bind)[https://www.isc.org/downloads/bind/]
- (ovsdb)[https://github.com/openvswitch/ovs]

A modified version of (quagga)[http://www.nongnu.org/quagga/index.html] is used and therefore, a quagga user must be created.

### Compiling

Simply running `make` will compile the code. Note that (jansson)[http://www.digip.org/jansson/] library must be installed and that this repository (submodules)[https://git-scm.com/book/nl/v1/Git-tools-Submodules] must be cloned.

### Deployment of SRN

1. Get the OVSDB server ready by running it on the controller node.
```
ovsdb-tool create sr.ovschema SR_test
ovsdb-server SR_test --remote=ptcp:6640:[::1] --remote=ptcp:6640:[<global-ipv6-address>]
```

2. Run your favorite DNS server on one of the nodes.

3. Run the controller with the command below. Performance will be better if it is located near the OVSDB server. The configuration file options are documented in *sr-ctrl/README.md*.
```
sr-ctrl/sr-ctrl <sr-ctrl_configfile>
```

3. Run the DNS proxy on the controller node. Performance will be better if it is located near the OVSDB server and the DNS server. The configuration file options are documented in *sr-dnsproxy/README.md*.
```
sr-dnsproxy/sr-dnsproxy <sr-dnsproxy_configfile>
```

4. Run the sr-routed deamons on each access router. The configuration file and its parameters are documented in *sr-routed* subfolders.
```
sr-routed/sr-routed <sr-routed_configfile>
```

5. Run generated *sr-nsd/zebra* and *sr-nsd/ospf6d* on one of the routers. The following option must be activated in ospf6d Quagga deamon configuration. Performance will be better if the selected router is located nea the OVSDB server.
```
router ospf6
  ovsdb_adv tcp <ovsdb-server-ip> 6640 SR_test
```

6. Run example applications like *sr-client/client* or *sr-testdns/sr-testdns* by specifying the address of the *sr-dnsproxy* as the DNS resolver

