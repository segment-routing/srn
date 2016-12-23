#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <ares_dns.h>

#include "proxy.h"

#define DNS_RCODE_REJECT 0x5
#define RRFIXEDSZ 10

#define MAX_LINE_LENGTH 3*(SLEN + 2)

struct queue_thread replies_waiting_controller;

struct srdb *srdb;

static void read_flowreq(struct srdb_entry *old_entry, struct srdb_entry *entry) {

	struct srdb_flowreq_entry *flowreq = (struct srdb_flowreq_entry *) entry;
	struct srdb_flowreq_entry *old_flowreq = (struct srdb_flowreq_entry *) old_entry;
  struct reply *reply = NULL;
  struct reply *tmp = NULL;

	print_debug("A new entry in the flowreq table is considered with uuid %s\n", old_flowreq->_row);

	if (flowreq->status != STATUS_PENDING && flowreq->status != STATUS_ALLOWED) {
		/* Check if its not our request */
		mqueue_walk_safe(&replies_waiting_controller, reply, tmp, struct reply *) {
	    if (!strncmp(old_flowreq->_row, reply->ovsdb_req_uuid, SLEN + 1)) {
				print_debug("A matching with a pending reply was found\n");
	      mqueue_remove(&replies_waiting_controller, (struct node *) reply);
	      break;
	    }
	  }
		if (((void *) reply) == (void *) &replies_waiting_controller) {
			return; /* Not for us */
		}

		/* Send a DNS reject by changing the RCODE and by leaving only the query record */
		DNS_HEADER_SET_RCODE(reply->data, DNS_RCODE_REJECT);
		DNS_HEADER_SET_ANCOUNT(reply->data, 0);
		DNS_HEADER_SET_NSCOUNT(reply->data, 0);
		DNS_HEADER_SET_ARCOUNT(reply->data, 0);
		uint16_t i = 0;
		for (i = 0; reply->data[DNS_HEADER_LENGTH + i] != 0; i++);
		reply->data_length = DNS_HEADER_LENGTH + i + 1 + 4; /* 4 bytes of Type and Class */

		print_debug("A DNS reject is going to be sent to the application\n");
	  if (sendto(server_sfd, reply->data, reply->data_length, 0,
	                 (struct sockaddr *) &reply->addr,
	                 reply->addr_len) != (int) reply->data_length) {
	    /* Drop the reject */
	    perror("Error sending the DNS reject to the client");
	  }

		FREE_POINTER(reply);
	}
}

static void read_flowstate(char *uuid, char *prefix, char *binding_segment) {

  struct reply *reply = NULL;
  struct reply *tmp = NULL;
	int i = 0;

	print_debug("A new entry in the flow state table is considered\n");

  /* Find the concerned reply */
  mqueue_walk_safe(&replies_waiting_controller, reply, tmp, struct reply *) {
    if (!strncmp(uuid, reply->ovsdb_req_uuid, SLEN + 1)) {
			print_debug("A matching with a pending reply was found\n");
      mqueue_remove(&replies_waiting_controller, (struct node *) reply);
      break;
    }
  }
	if (((void *) reply) == (void *) &replies_waiting_controller) {
		return; /* Not for us */
	}

  /* Add the binding segment to the reply */

	char *srh_rr = reply->data + reply->data_length;
	char *name = reply->data + DNS_RR_NAME_OFFSET;
	unsigned char binding_segment_addr[16];
	if (inet_pton(AF_INET6, binding_segment, binding_segment_addr) != 1) {
		fprintf(stderr, "Not a valid IPv6 address received: %s\n", binding_segment);
		goto free_reply;
	}
	unsigned char prefix_segment_addr[16];
	if (inet_pton(AF_INET6, prefix, prefix_segment_addr) != 1) {
		fprintf(stderr, "Not a valid IPv6 address received: %s\n", prefix);
		goto free_reply;
	}

	/* Change DNS header */
	DNS_HEADER_SET_ARCOUNT(reply->data, DNS_HEADER_ARCOUNT(reply->data) + 1);

	/* Set name */
	for (i = 0; name[i] != 0; i++) {
		srh_rr[i] = name[i];
	}
	srh_rr[i] = name[i];
	reply->data_length = reply->data_length + i + 1;
	srh_rr = reply->data + reply->data_length;

	/* Set RR fields */
	DNS_RR_SET_TYPE(srh_rr, T_SRH);
	DNS_RR_SET_CLASS(srh_rr, C_IN);
	DNS_RR_SET_TTL(srh_rr, 0); /* TODO Change this value */
	DNS_RR_SET_LEN(srh_rr, 2 + 2*16); /* Status + 1 prefix + 1 binding segment */
	reply->data_length = reply->data_length + RRFIXEDSZ + 2 + 2*16;
	srh_rr += RRFIXEDSZ;

	/* Set RR data (status + prefix + binding segment) */
	DNS__SET16BIT(srh_rr, 0);
	srh_rr += 2;
	memcpy(srh_rr, prefix_segment_addr, 16);
	srh_rr += 16;
	memcpy(srh_rr, binding_segment_addr, 16);

  /* Send reply to the client */
	print_debug("A reply is going to be sent to the application\n");
  if (sendto(server_sfd, reply->data, reply->data_length, 0,
                 (struct sockaddr *) &reply->addr,
                 reply->addr_len) != (int) reply->data_length) {
    /* Drop the reply */
    perror("Error sending the reply to the client");
    /* TODO What to do then ??? */
  }

free_reply:
  FREE_POINTER(reply);
}

static void *thread_monitor(void *_arg) {

  struct monitor_arg *arg = _arg;
	int ret;

	print_debug("A monitor thread has started\n");

	ret = srdb_monitor(arg->srdb, arg->table, arg->columns);

	print_debug("A monitor thread has finished\n");

	return (void *)(intptr_t)ret;
}

static void *thread_flowstate_monitor(void *_arg) {

	char *pipe_path = (char *) _arg;
  int err = 0;
	int i = 0;
  fd_set read_fds;
  struct timeval timeout;
	FILE *fp;
	int fd = -1;

	print_debug("A monitor thread for the flow state has started\n");

	fp = fopen(pipe_path, "r");
	if (!fp) {
		perror("Cannot open file");
		return NULL;
	}
	fd = fileno(fp);

	while (!stop) {

    FD_ZERO(&read_fds);
		FD_SET(fd, &read_fds);
    timeout.tv_sec = TIMEOUT_LOOP;
    timeout.tv_usec = 0;
    err = select(fd + 1, &read_fds, NULL, NULL, &timeout);
    if (err < 0) {
      perror("Select fail");
      break;
    }

		if (FD_ISSET(fd, &read_fds)) {
			char line [MAX_LINE_LENGTH];
			if (!fgets(line, MAX_LINE_LENGTH, fp)) {
				perror("Cannot read line");
				break;
			}

			/* Line parsing */
			char *uuid = line;
			for (i = 0; line[i] != ' '; i++);
			line[i] = '\0';
			char *prefix = line + i + 1;
			for (i++; line[i] != ' '; i++);
			line[i] = '\0';
			char *binding_segment = line + i + 1;
			for (i++; line[i] != '\n' && line[i] != '\0'; i++);
			line[i] = '\0';

			/* Send back a reply to the application */
			read_flowstate(uuid, prefix, binding_segment);
		}
	}

	fclose(fp);

	print_debug("A monitor thread for the flow state has stopped\n");
	return NULL;
}

int init_monitor(const char *listen_port, struct monitor_arg *args, __attribute__((unused)) pthread_t *monitor_flowreqs_thread, pthread_t *monitor_flows_thread) {

  struct addrinfo hints;
  struct addrinfo *result, *rp;

  int status = 0;

  /* Init server socket */
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
  hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
  hints.ai_protocol = 0;          /* Any protocol */
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  status = getaddrinfo(NULL, listen_port, &hints, &result);
  if (status != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
    goto out_err;
  }

  for (rp = result; rp != NULL; rp = rp->ai_next) {
    server_sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (server_sfd == -1)
      continue;

    if (bind(server_sfd, rp->ai_addr, rp->ai_addrlen) == 0)
      break;

    CLOSE_FD(server_sfd);
  }

  freeaddrinfo(result);

  if (rp == NULL) {
    fprintf(stderr, "Could not bind\n");
    status = -1;
    goto out_err;
  }

  /* Init ovsdb monitoring */
	struct srdb_table *tbl;
  struct ovsdb_config ovsdb_conf;

  /* TODO Add config file for that */
  snprintf(ovsdb_conf.ovsdb_client, SLEN + 1, "ovsdb-client");
  snprintf(ovsdb_conf.ovsdb_server, SLEN + 1, "tcp:[::1]:6640");
  snprintf(ovsdb_conf.ovsdb_database, SLEN + 1, "SR_test");

  srdb = srdb_new(&ovsdb_conf);

	tbl = srdb_table_by_name(srdb->tables, "FlowReq");
	tbl->read_update = read_flowreq;
	args[0].srdb = srdb;
	args[0].table = tbl;
	args[0].columns = "!initial,!delete,!insert";
	pthread_create(monitor_flowreqs_thread, NULL, thread_monitor, (void *)&args[0]);

	pthread_create(monitor_flows_thread, NULL, thread_flowstate_monitor, (void *) DNS_FIFO_PATH); /* TODO Put in a config file */

  mqueue_init(&replies_waiting_controller, MAX_QUERIES);

out_err:
  return status;
}

void close_monitor() {
  srdb_destroy(srdb);
  mqueue_destroy(&replies_waiting_controller);
}
