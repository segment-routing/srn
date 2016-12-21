#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "proxy.h"

struct queue_thread replies_waiting_controller;

struct srdb *srdb;

// TODO Complete
//static void read_flowreq(__attribute__((unused)) struct srdb_entry *entry) {
//
//	/* TODO If status is rejected => drop the reply (for the moment) */
//}

static void read_flowstate(struct srdb_entry *entry) {

	struct srdb_flow_entry *flowstate = (struct srdb_flow_entry *) entry;
  struct reply *reply = NULL;
  struct reply *tmp = NULL;

  /* Find the concerned reply */
  mqueue_walk_safe(&replies_waiting_controller, reply, tmp, struct reply *) {
    if (!strncmp(flowstate->request_uuid, reply->ovsdb_req_uuid, SLEN + 1)) {
      mqueue_remove(&replies_waiting_controller, (struct node *) reply);
      break;
    }
  }

  /* TODO Insert mapping */

  /* TODO Add the binding segment to the reply */

  /* Send reply to the client */
  if (sendto(server_sfd, reply->data, reply->data_length, 0,
                 (struct sockaddr *) &reply->addr,
                 reply->addr_len) != (int) reply->data_length) {
    /* Drop the reply */
    perror("Error sending the reply to the client");
    /* TODO What to do then ??? */
  }

  FREE_POINTER(reply);
}

static void *thread_monitor(void *_arg) {

  struct monitor_arg *arg = _arg;
	int ret;

	ret = srdb_monitor(arg->srdb, arg->table, arg->columns);

	return (void *)(intptr_t)ret;
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

  /* TODO Add arguments for that */
  snprintf(ovsdb_conf.ovsdb_client, SLEN + 1, "ovsdb-client");
  snprintf(ovsdb_conf.ovsdb_server, SLEN + 1, "tcp:[::1]:6640");
  snprintf(ovsdb_conf.ovsdb_database, SLEN + 1, "SR_test");

  srdb = srdb_new(&ovsdb_conf);

  /* TODO Wait for the function to set an update callback */
	/*tbl = srdb_table_by_name(srdb->tables, "FlowReq");
	srdb_set_readupdate_cb(srdb, "FlowReq", read_flowreq);
	args[0].srdb = _cfg.srdb;
	args[0].table = tbl;
	args[0].columns = "!initial,!delete,!insert";
	pthread_create(monitor_flowreqs_thread, NULL, thread_monitor, (void *)&args[0]);*/

	tbl = srdb_table_by_name(srdb->tables, "FlowState");
	srdb_set_read_cb(srdb, "FlowState", read_flowstate);
	args[0].srdb = srdb;
	args[0].table = tbl;
	args[0].columns = "!initial,!delete,!modify";
	pthread_create(monitor_flows_thread, NULL, thread_monitor, (void *)&args[0]);

  mqueue_init(&replies_waiting_controller, MAX_QUERIES);

out_err:
  return status;
}

void close_monitor() {
  // TODO Free ovsdb monitoring
  srdb_destroy(srdb);
  mqueue_destroy(&replies_waiting_controller);
}
