# SRN controller

Usage:

```bash
$ ./sr-ctrl [-d] <sr-ctrl_configfile>
```

We can use the "-d" option for dry run.
Meaning that the program only tests the syntax of the configuration file.

## Configuration

The SRN controller has the following parameters:

- ovsdb_client The command to run to execute ovsdb-client executable
- ovsdb_server The OVSDB server specification as defined in [ovsdb-client\(1)](https://www.systutorials.com/docs/linux/man/1-ovsdb-client/)
- ovsdb_database The name of the database on the OVSDB server
- rules_file The name of the rules configuration file
- worker_threads The number of threads answering to requests from applications
- req_buffer_size The size of the request queue; in case of overflow, requests are dropped
- ntransacts The number of threads interacting wih the OVSDB server
- zlog_conf_file The path to a logging file

The following snippet shows a working configuration for a controller
on the same machine as the OVSDB server listening on port 6640:

```
ovsdb_client "ovsdb-client"
ovsdb_server "tcp:[::1]:6640"
ovsdb_database "SR_test"
rules_file "rules.conf"
worker_threads 1
req_buffer_size 10
ntransacts 1
zlog_conf_file "output.log"
```

