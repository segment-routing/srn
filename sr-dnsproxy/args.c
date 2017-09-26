#include <stdlib.h>
#include <sys/select.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>

#include <ares.h>

#include "proxy.h"

#define DEFAULT_DNS_PORT "53"

struct config cfg;

#define READ_STRING(b, arg, dst) sscanf(b, #arg " \"%[^\"]\"", (dst)->arg)
#define READ_INT(b, arg, dst) sscanf(b, #arg " %i", &(dst)->arg)


void config_set_defaults()
{
	strcpy(cfg.ovsdb_conf.ovsdb_client, "ovsdb-client");
	strcpy(cfg.ovsdb_conf.ovsdb_server, "ovsdb-server");
	strcpy(cfg.ovsdb_conf.ovsdb_database, "SR_test");
	strcpy(cfg.client_server_fifo, FIFO_CLIENT_SERVER_NAME);
	strcpy(cfg.router_name, "A");
	strcpy(cfg.dns_server_port, DEFAULT_DNS_PORT);
	strcpy(cfg.proxy_listen_port, "2000");
	cfg.ovsdb_conf.ntransacts = 1;
	cfg.max_queries = 50;
}

int load_args(int argc, char **argv, const char **conf, int *dryrun)
{
	int c;
	opterr = 0;

	while ((c = getopt(argc, argv, "d")) != -1)
		switch (c)
		{
			case 'd':
				*dryrun = 1;
				break;
			case '?':
				fprintf(stderr, "Unknown option `-%c'.\n", optopt);
				return -1;
			default:
				return -1;
		}

	if (optind == argc - 1)
		*conf = argv[optind];
	else if (optind > argc)
		return -1;
	return 0;
}

/* Some of the code was taken from the "adig.c" file in the c-ares library */
int load_config(const char *fname, int *optmask, struct ares_addr_node **servers)
{
	char buf[128];
	int ret = 0;
	FILE *fp;
	char dns_server [SLEN + 1];
	struct ares_addr_node *srvr = NULL;
	struct hostent *hostent = NULL;

	fp = fopen(fname, "r");
	if (!fp) {
		perror("Cannot open config file\n");
		destroy_addr_list(*servers);
		*servers = NULL;
		return -1;
	}

	while (fgets(buf, 128, fp)) {
		strip_crlf(buf);
		if (READ_STRING(buf, ovsdb_client, &cfg.ovsdb_conf))
			continue;
		if (READ_STRING(buf, ovsdb_server, &cfg.ovsdb_conf))
			continue;
		if (READ_STRING(buf, ovsdb_database, &cfg.ovsdb_conf))
			continue;
		if (READ_INT(buf, ntransacts, &cfg.ovsdb_conf)) {
			if (!cfg.ovsdb_conf.ntransacts)
				cfg.ovsdb_conf.ntransacts = 1;
			continue;
		}
		if (READ_STRING(buf, client_server_fifo, &cfg))
			continue;
		if (READ_STRING(buf, router_name, &cfg))
			continue;
		if (READ_STRING(buf, dns_server_port, &cfg))
			continue;
		if (READ_STRING(buf, proxy_listen_port, &cfg))
			continue;
		if (READ_INT(buf, max_queries, &cfg)) {
			if (!cfg.max_queries)
				cfg.max_queries = 1;
			continue;
		}
		if (sscanf(buf, "dns_server \"%[^\"]\"", dns_server)) {
			srvr = malloc(sizeof(struct ares_addr_node));
			if (!srvr) {
				fprintf(stderr, "Out of memory!\n");
				goto out_err;
			}
			append_addr_list(servers, srvr);
			if (ares_inet_pton(AF_INET, dns_server, &srvr->addr.addr4) > 0)
				srvr->family = AF_INET;
			else if (ares_inet_pton(AF_INET6, dns_server, &srvr->addr.addr6) > 0)
				srvr->family = AF_INET6;
			else {
				hostent = gethostbyname(optarg);
				if (!hostent) {
					fprintf(stderr, "adig: server %s not found.\n", dns_server);
					goto out_err;
				}
				switch (hostent->h_addrtype) {
				case AF_INET:
					srvr->family = AF_INET;
					memcpy(&srvr->addr.addr4, hostent->h_addr_list[0],
					       sizeof(srvr->addr.addr4));
					break;
				case AF_INET6:
					srvr->family = AF_INET6;
					memcpy(&srvr->addr.addr6, hostent->h_addr_list[0],
					       sizeof(srvr->addr.addr6));
					break;
				default:
					fprintf(stderr, "adig: server %s unsupported address family.\n", dns_server);
					goto out_err;
				}
			}
			/* Notice that calling ares_init_options() without servers in the
			 * options struct and with ARES_OPT_SERVERS set simultaneously in
			 * the options mask, results in an initialization with no servers.
			 * When alternative name servers have been specified these are set
			 * later calling ares_set_servers() overriding any existing server
			 * configuration. To prevent initial configuration with default
			 * servers that will be discarded later, ARES_OPT_SERVERS is set.
			 * If this flag is not set here the result shall be the same but
			 * ares_init_options() will do needless work. */
			*optmask |= ARES_OPT_SERVERS;
			continue;
		}
out_err:
		destroy_addr_list(*servers);
		*servers = NULL;
		fprintf(stderr, "parse error: unknown line `%s'.", buf);
		ret = -1;
		break;
	}

	fclose(fp);
	return ret;
}
