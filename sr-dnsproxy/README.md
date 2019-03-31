# SRN DNS proxy

Usage:

```bash
$ ./sr-dnsproxy [-d] <sr-dnsproxy_configfile>
```

We can use the "-d" option for dry run.
Meaning that the program only tests the syntax of the configuration file before exiting.

## Configuration

The DNS proxy has the following parameters:

- ovsdb_client The command to run to execute ovsdb-client executable
- ovsdb_server The OVSDB server specification as defined in [ovsdb-client(1)](https://www.systutorials.com/docs/linux/man/1-ovsdb-client/)
- ovsdb_database The name of the database on the OVSDB server
- router_name The name of the router in the NodeState database
- max_queries The maximum number of requests in the queue before dropping
- proxy_listen_addr The address on which the DNS proxy listens
- proxy_listen_port The port on which the DNS proxy listens
- dns_server_port The port of the actual DNS server
- dns_server The address of the actual DNS server
- client_server_fifo The path where an internal fifo will be created (the file should not exist prior to the execution of the program)
- ntransacts The number of threads interacting wih the OVSDB server
- zlog_conf_file The path to a logging file

The following snippet shows a working configuration for a DNS proxy
on the same machine as the OVSDB server listening on port 6640
and the actual DNS server listening on port 2000:

```
ovsdb_client "ovsdb-client"
ovsdb_server "tcp:[::1]:6640"
ovsdb_database "SR_test"
router_name "RouterA"
max_queries 500
proxy_listen_addr "::"
proxy_listen_port "53"
dns_server_port "2000"
dns_server "::1"
ntransacts 1
client_server_fifo "client_server.fifo"
zlog_conf_file "output.log"
```

