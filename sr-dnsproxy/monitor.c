#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <ares_dns.h>
#include <srdns.h>

#include <jansson.h>

#include "proxy.h"

#define DNS_RCODE_REJECT 0x5
#define RRFIXEDSZ 10

#define MAX_LINE_LENGTH 3*(SLEN + 2)

struct queue_thread replies_waiting_controller;

struct srdb *srdb;

static int read_flowreq(struct srdb_entry *entry,
			struct srdb_entry *diff __unused,
			unsigned int fmask)
{
	struct srdb_flowreq_entry *flowreq;
	struct reply *reply, *tmp;

	flowreq = (struct srdb_flowreq_entry *)entry;

	if (!(fmask & ENTRY_MASK(FREQ_STATUS)))
		return -1;

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
			   (struct sockaddr *) &reply->addr, reply->addr_len) != (int) reply->data_length) {
			/* Drop the reject */
			perror("Error sending the DNS reject to the client");
		}

		FREE_POINTER(reply);
	}

	return stop;
}

static int read_flowstate(struct srdb_entry *entry)
{
	struct reply *reply = NULL;
	struct reply *tmp = NULL;
	int i = 0, j = 0;
	struct srdb_flow_entry *flowstate = (struct srdb_flow_entry *) entry;
	char *dns_fixed_hdr = NULL;
	char *srh_rr = NULL;
	char *name = NULL;

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

	json_t *providers = json_loads(flowstate->sourceIPs, 0, NULL);
	json_t *bsids = json_loads(flowstate->bsid, 0, NULL);
	json_t *provider = NULL;
	json_array_foreach(providers, i, provider) {

		if (!json_is_integer(json_array_get(provider, 0)) ||
		    !json_is_string(json_array_get(provider, 1)) ||
		    !json_is_integer(json_array_get(provider, 2))) {
			fprintf(stderr, "Malformed Provider %dth field: %s\n", i, flowstate->sourceIPs);
			goto free_json;
		}  else if (!json_is_string(json_array_get(bsids, i))) {
			fprintf(stderr, "Malformed bsid %dth field: %s\n", i, flowstate->bsid);
			goto free_json;
		}

		unsigned short prefix_priority = (unsigned short) json_integer_value(json_array_get(provider, 0));
		const char *prefix_addr_str = json_string_value(json_array_get(provider, 1));
		unsigned char prefix_length = (unsigned char) json_integer_value(json_array_get(provider, 2));
		const char *bsid_str = json_string_value(json_array_get(bsids, i));

		DNS_HEADER_SET_ARCOUNT(reply->data, DNS_HEADER_ARCOUNT(reply->data) + 1);

		dns_fixed_hdr = reply->data + reply->data_length;
		name = reply->data + DNS_HEADER_LENGTH;

		/* Set name */
		for (j = 0; name[j] != 0; j++) {
			dns_fixed_hdr[j] = name[j];
		}
		dns_fixed_hdr[j] = name[j];
		reply->data_length = reply->data_length + j + 1;
		dns_fixed_hdr = reply->data + reply->data_length;

		/* Set RR fields */
		DNS_RR_SET_TYPE(dns_fixed_hdr, T_SRH);
		DNS_RR_SET_CLASS(dns_fixed_hdr, C_IN);
		DNS_RR_SET_LEN(dns_fixed_hdr, 35);
		DNS_RR_SET_TTL(dns_fixed_hdr, 0); /* TODO Change this value */
		srh_rr = dns_fixed_hdr + RRFIXEDSZ;

		DNS__SET16BIT(srh_rr, prefix_priority);
		printf("prefix_priority = %u prefix_priority = %u byte %u byte %u", DNS__16BIT(srh_rr), prefix_priority, (unsigned char) srh_rr[0], (unsigned char) srh_rr[1]);
		srh_rr += 2;
		if (inet_pton(AF_INET6, prefix_addr_str, srh_rr) != 1) {
			fprintf(stderr, "Not a valid IPv6 address received as Provider prefix: %s\n", prefix_addr_str);
			goto free_json;
		}
		srh_rr += 16;
		*srh_rr = prefix_length;
		srh_rr++;
		if (inet_pton(AF_INET6, bsid_str, srh_rr) != 1) {
			fprintf(stderr, "Not a valid IPv6 address received as BSID: %s\n", bsid_str);
			goto free_json;
		}
		srh_rr += 16;

		reply->data_length += RRFIXEDSZ + DNS_RR_LEN(dns_fixed_hdr);
	}

#if DEBUG_PERF
	if (clock_gettime(CLOCK_MONOTONIC, &reply->reply_forward_time)) {
		perror("Cannot get reply_forward time");
	}
	struct timespec result;
	clock_getres(CLOCK_MONOTONIC, &result);
	printf("Query %d arrived at %ld.%ld with resolution %ld.%ld\n",
		DNS_HEADER_QID(reply->data), reply->query_rcv_time.tv_sec,
		reply->query_rcv_time.tv_nsec, result.tv_sec, result.tv_nsec);
	printf("Query %d was forwarded to the real DNS server at %ld.%ld\n",
		DNS_HEADER_QID(reply->data), reply->query_forward_time.tv_sec,
		reply->query_forward_time.tv_nsec);
 	printf("Query %d got a reply from the real DNS server at %ld.%ld\n",
		DNS_HEADER_QID(reply->data), reply->reply_rcv_time.tv_sec,
		reply->reply_rcv_time.tv_nsec);
 	printf("Query %d triggered a flow request to the controller at %ld.%ld\n",
		DNS_HEADER_QID(reply->data), reply->controller_query_time.tv_sec,
		reply->controller_query_time.tv_nsec);
 	printf("Query %d after having triggered a flow request to the controller at %ld.%ld\n",
		DNS_HEADER_QID(reply->data), reply->controller_after_query_time.tv_sec,
		reply->controller_after_query_time.tv_nsec);
 	printf("Query %d received a response from the controller at %ld.%ld\n",
		DNS_HEADER_QID(reply->data), reply->controller_reply_time.tv_sec,
		reply->controller_reply_time.tv_nsec);
 	printf("Query %d triggered the final DNS reply at %ld.%ld\n",
		DNS_HEADER_QID(reply->data), reply->reply_forward_time.tv_sec,
		reply->reply_forward_time.tv_nsec);
#endif

	/* Send reply to the client */
	print_debug("A reply is going to be sent to the application\n");
	if (sendto(server_sfd, reply->data, reply->data_length, 0,
		   (struct sockaddr *) &reply->addr,
		   reply->addr_len) != (int) reply->data_length) {
		/* Drop the reply */
		perror("Error sending the reply to the client");
	}

free_json:
	json_decref(providers);
	json_decref(bsids);
	FREE_POINTER(reply);
	return stop;
}

int init_monitor(void)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;

	int status = 0;

	/* Init server socket */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET6;		/* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
	hints.ai_flags = AI_PASSIVE;		/* For wildcard IP address */
	hints.ai_protocol = 0;					/* Any protocol */
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
		goto out_err;
	}

	/* Init ovsdb monitoring */
	cfg.ovsdb_conf.ntransacts = 1;
	srdb = srdb_new(&cfg.ovsdb_conf);
	if (!srdb) {
		fprintf(stderr, "Cannot connect to the database\n");
		goto out_err;
	}

	if (srdb_monitor(srdb, "FlowReq", MON_UPDATE, NULL, read_flowreq, NULL,
			 false, true) < 0) {
		pr_err("failed to start FlowReq monitor.");
		goto out_err;
	}

	if (srdb_monitor(srdb, "FlowState", MON_INSERT, read_flowstate, NULL,
			 NULL, false, true) < 0) {
		pr_err("failed to start FlowState monitor.");
		goto out_err;
	}

	mqueue_init(&replies_waiting_controller, cfg.max_queries);

out:
	return status;
out_err:
	status = -1;
	goto out;
}

void close_monitor()
{
	srdb_destroy(srdb);
	mqueue_destroy(&replies_waiting_controller);
}
