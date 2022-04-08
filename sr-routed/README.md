# SRN Routing daemon

Usage:

```bash
$ ./sr-routed [-d] <sr-routed_configfile>
```

We can use the "-d" option for dry run.
Meaning that the program only tests the syntax of the configuration file before exiting.

## Configuration

The routing daemon has the following parameters:

- ovsdb_client The command to run to execute ovsdb-client executable
- ovsdb_server The OVSDB server specification as defined in [ovsdb-client\(1)](https://www.systutorials.com/docs/linux/man/1-ovsdb-client/)
- ovsdb_database The name of the database on the OVSDB server
- router_name The name of the router in the NodeState database
- localsid The name of the Local SID Table that will parse the segments (see [documentation](https://segment-routing.org/index.php/Implementation/AdvancedConf)).
- ingress_iface The name of an interface of the router (the actual interface used does not matter as long as it is not the loopback).
- ntransacts The number of threads interacting wih the OVSDB server
- zlog_conf_file The path to a logging file

The following snippet shows a working configuration for a DNS proxy
on the same machine as the OVSDB server listening on port 6640
and the local SID table is called RouterA.localsid:

```
ovsdb_client "ovsdb-client"
ovsdb_server "tcp:[::1]:6640"
ovsdb_database "SR_test"
router_name "RouterA"
localsid "RouterA.localsid"
ingress_iface "RouterA-eth0"
ntransacts 1
client_server_fifo "client_server.fifo"
zlog_conf_file "output.log"
```

