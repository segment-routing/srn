#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <ares_dns.h>
#include <srdns.h>

#include "proxy.h"

#define DNS_RCODE_REJECT 0x5
#define RRFIXEDSZ 10

#define MAX_LINE_LENGTH 3*(SLEN + 2)

struct queue_thread replies_waiting_controller;

struct srdb *srdb;

struct queue_thread transact_input;
struct queue_thread transact_output;

static int read_flowreq(__attribute__((unused)) struct srdb_entry *old_entry, struct srdb_entry *entry) {

	struct srdb_flowreq_entry *flowreq = (struct srdb_flowreq_entry *) entry;
  struct reply *reply = NULL;
  struct reply *tmp = NULL;

	print_debug("A modified entry in the flowreq table is considered with id %s and status %d\n", flowreq->request_id, flowreq->status);

	if (flowreq->status != REQ_STATUS_PENDING && flowreq->status != REQ_STATUS_ALLOWED) {
		print_debug("Check if the rejected reply is for this router\n");
		/* Check if its not our request */
		mqueue_walk_safe(&replies_waiting_controller, reply, tmp, struct reply *) {
			print_debug("Check an entry with uuid %s\n", reply->ovsdb_req_uuid);
	    if (!strncmp(flowreq->request_id, reply->ovsdb_req_uuid, SLEN + 1)) {
				print_debug("A matching with a pending reply was found\n");
	      mqueue_remove(&replies_waiting_controller, (struct llnode *) reply);
	      break;
	    }
	  }
		if (((void *) reply) == (void *) &replies_waiting_controller) {
			return stop; /* Not for us or not rejected */
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

	return stop;
}

static int read_flowstate(struct srdb_entry *entry) {

  struct reply *reply = NULL;
  struct reply *tmp = NULL;
	int i = 0;
	struct srdb_flow_entry *flowstate = (struct srdb_flow_entry *) entry;

	print_debug("A new entry in the flow state table is considered\n");
#if DEBUG_PERF
	struct timespec controller_reply_time;
  if (clock_gettime(CLOCK_MONOTONIC, &controller_reply_time)) {
    perror("Cannot get controller_reply time");
  }
#endif

  /* Find the concerned reply */
  mqueue_walk_safe(&replies_waiting_controller, reply, tmp, struct reply *) {
    if (!strncmp(flowstate->request_id, reply->ovsdb_req_uuid, SLEN + 1)) {
			print_debug("A matching with a pending reply was found\n");
      mqueue_remove(&replies_waiting_controller, (struct llnode *) reply);
      break;
    }
  }
	if (((void *) reply) == (void *) &replies_waiting_controller) {
		return stop; /* Not for us */
	}
#if DEBUG_PERF
	reply->controller_reply_time = controller_reply_time;
#endif

  /* Add the binding segment to the reply */

	char *srh_rr = reply->data + reply->data_length;
	char *name = reply->data + DNS_HEADER_LENGTH;
	unsigned char binding_segment_addr[16];
	if (inet_pton(AF_INET6, flowstate->bsid, binding_segment_addr) != 1) {
		fprintf(stderr, "Not a valid IPv6 address received: %s\n", flowstate->bsid);
		goto free_reply;
	}
	unsigned char prefix_segment_addr[16];
	if (inet_pton(AF_INET6, flowstate->dstaddr, prefix_segment_addr) != 1) { // TODO This should be changed by a real source prefix
		fprintf(stderr, "Not a valid IPv6 address received: %s\n", flowstate->dstaddr); // TODO This should be changed by a real source prefix
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


#if DEBUG_PERF
  if (clock_gettime(CLOCK_MONOTONIC, &reply->reply_forward_time)) {
    perror("Cannot get reply_forward time");
  }
	struct timespec result;
	clock_getres(CLOCK_MONOTONIC, &result);
	printf("Query %d arrived at %ld.%ld with resolution %ld.%ld\n",
       	 DNS_HEADER_QID(reply->data), reply->query_rcv_time.tv_sec, reply->query_rcv_time.tv_nsec, result.tv_sec, result.tv_nsec);
	printf("Query %d was forwarded to the real DNS server at %ld.%ld\n",
       	 DNS_HEADER_QID(reply->data), reply->query_forward_time.tv_sec, reply->query_forward_time.tv_nsec);
 	printf("Query %d got a reply from the real DNS server at %ld.%ld\n",
       	 DNS_HEADER_QID(reply->data), reply->reply_rcv_time.tv_sec, reply->reply_rcv_time.tv_nsec);
 	printf("Query %d triggered a flow request to the controller at %ld.%ld\n",
       	 DNS_HEADER_QID(reply->data), reply->controller_query_time.tv_sec, reply->controller_query_time.tv_nsec);
 	printf("Query %d after having triggered a flow request to the controller at %ld.%ld\n",
       	 DNS_HEADER_QID(reply->data), reply->controller_after_query_time.tv_sec, reply->controller_after_query_time.tv_nsec);
 	printf("Query %d received a response from the controller at %ld.%ld\n",
       	 DNS_HEADER_QID(reply->data), reply->controller_reply_time.tv_sec, reply->controller_reply_time.tv_nsec);
 	printf("Query %d triggered the final DNS reply at %ld.%ld\n",
       	 DNS_HEADER_QID(reply->data), reply->reply_forward_time.tv_sec, reply->reply_forward_time.tv_nsec);
#endif

  /* Send reply to the client */
	print_debug("A reply is going to be sent to the application\n");
  if (sendto(server_sfd, reply->data, reply->data_length, 0,
                 (struct sockaddr *) &reply->addr,
                 reply->addr_len) != (int) reply->data_length) {
    /* Drop the reply */
    perror("Error sending the reply to the client");
  }

free_reply:
  FREE_POINTER(reply);
	return stop;
}

static void *thread_monitor(void *_arg) {

  struct monitor_arg *arg = _arg;
	int ret;

	print_debug("A monitor thread has started\n");

	ret = srdb_monitor(arg->srdb, arg->table, arg->modify, arg->initial, arg->insert, arg->delete);

	print_debug("A monitor thread has finished\n");

	return (void *)(intptr_t)ret;
}

static void *thread_transact(__attribute__((unused)) void *_arg) {

	srdb_transaction(&cfg.ovsdb_conf, &transact_input, &transact_output);
	return NULL;
}

int init_monitor(struct monitor_arg *args, pthread_t *monitor_flowreqs_thread,
		 pthread_t *monitor_flows_thread,
		 pthread_t *transact_thread) {

  struct addrinfo hints;
  struct addrinfo *result, *rp;

  int status = 0;

  /* Init server socket */
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_INET6;    /* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
  hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
  hints.ai_protocol = 0;          /* Any protocol */
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  status = getaddrinfo(NULL, cfg.proxy_listen_port, &hints, &result);
  if (status != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
    goto out_err;
  }

  for (rp = result; rp != NULL; rp = rp->ai_next) {
    server_sfd = socket(rp->ai_family, rp->ai_socktype | SOCK_CLOEXEC, rp->ai_protocol);
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
  srdb = srdb_new(&cfg.ovsdb_conf);
	if (!srdb) {
		fprintf(stderr, "Cannot connect to the database\n");
		status = -1;
		goto out_err;
	}

	tbl = srdb_table_by_name(srdb->tables, "FlowReq");
	tbl->read_update = read_flowreq;
	args[0].srdb = srdb;
	args[0].table = tbl;
	args[0].initial = 0;
	args[0].modify = 1;
	args[0].insert = 0;
	args[0].delete = 0;
	pthread_create(monitor_flowreqs_thread, NULL, thread_monitor, (void *) &args[0]);

	tbl = srdb_table_by_name(srdb->tables, "FlowState");
	tbl->read = read_flowstate;
	args[1].srdb = srdb;
	args[1].table = tbl;
	args[1].initial = 0;
	args[1].modify = 0;
	args[1].insert = 1;
	args[1].delete = 0;
	pthread_create(monitor_flows_thread, NULL, thread_monitor, (void *) &args[1]);

  mqueue_init(&replies_waiting_controller, max_queries);

	/* Init transaction threads */
	mqueue_init(&transact_input, max_queries);
	mqueue_init(&transact_output, max_queries);
	pthread_create(transact_thread, NULL, thread_transact, NULL);

out_err:
  return status;
}

void close_monitor() {
  srdb_destroy(srdb);
  mqueue_destroy(&replies_waiting_controller);
  mqueue_destroy(&transact_input);
  mqueue_destroy(&transact_output);
}
