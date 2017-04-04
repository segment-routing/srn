#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <jansson.h>

#include "srdb.h"
#include "misc.h"

#define BUFLEN 1024
#define JSON_BUFLEN 5000
#define READ_OVSDB_SERVER(b, addr, port) sscanf(b, "tcp:[%[^]]]:%hu", addr, port)
#define BOOL_TO_STR(boolean) boolean ? "true" : "false"

#define MAX_PENDING_MSG 500

static int parse_ovsdb_update_tables(json_t *table_updates, int initial,
				     int (*callback)(const char *,
					     	     json_t *, int, void *),
				     void *arg)
{
	int ret = 0;
	json_t *modification = NULL;
	const char *uuid = NULL;

	json_object_foreach(table_updates, uuid, modification) {
		if ((ret = callback(uuid, modification, initial, arg))) {
			break;
		}
	}
	return ret;
}

static int parse_ovsdb_monitor_reply(json_t *monitor_reply, const char *table,
	                             int (*callback)(const char *, json_t *, int,
						     void *), void *arg)
{
	if (!json_is_null(json_object_get(monitor_reply, "error"))) {
		fprintf(stderr, "There is a non-null error message in the monitor reply\n");
		return -1;
	}
	json_t *updates = json_object_get(monitor_reply, "result");
	if (!updates) {
		fprintf(stderr, "Monitor reply parsing issue: No result found\n");
		return -1;
	}
	json_t *table_updates = json_object_get(updates, table);
	if (!table_updates) {
		// No initial data
		return 0;
	}
	return parse_ovsdb_update_tables(table_updates, 1, callback, arg);
}

static int parse_ovsdb_update(json_t *update, const char *table,
		              int (*callback)(const char *, json_t *, int, void *),
					      void *arg)
{
	json_t *params = json_object_get(update, "params");
	if (!params) {
		fprintf(stderr, "Update parsing issue: params key not found\n");
		return -1;
	}
	if (json_array_size(params) < 2) {
		fprintf(stderr, "Update parsing issue: No params\n");
		return -1;
	}
	json_t *updates = json_array_get(params, 1);
	if (!updates) {
		fprintf(stderr, "Update parsing issue: No update found\n");
		return -1;
	}
	json_t *table_updates = json_object_get(updates, table);
	if (!table_updates) {
		fprintf(stderr, "Update parsing issue: No update for table %s found\n", table);
		return -1;
	}
	return parse_ovsdb_update_tables(table_updates, 0, callback, arg);
}

static inline int parse_ovsdb_echo(json_t *msg)
{
	json_t *method = json_object_get(msg, "method");
	return (!method || !json_is_string(method) || strcmp(json_string_value(method), "echo"));
}

static int ovsdb_socket(const struct ovsdb_config *conf)
{
	int sfd = -1;
	char str_addr[BUFLEN+1];
	unsigned short port;

	READ_OVSDB_SERVER(conf->ovsdb_server, str_addr, &port);
	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(port),
		.sin6_flowinfo = 0,
		.sin6_scope_id = 0
	};
	inet_pton(AF_INET6, str_addr, &addr.sin6_addr);

	sfd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (connect(sfd, (struct sockaddr *) &addr, sizeof(addr))) {
		perror("connect to ovsdb server");
		goto close_sfd;
	}

	int i = 1;
	if (setsockopt(sfd, SOL_TCP, TCP_NODELAY, &i, sizeof(i)) < 0) {
		perror("setsockopt");
		goto close_sfd;
	}

out:
	return sfd;
close_sfd:
	close(sfd);
	sfd = -1;
	goto out;
}

static int ovsdb_monitor(const struct ovsdb_config *conf, const char *table,
			 int modify, int initial, int insert, int delete,
			 int (*callback)(const char *, json_t *, int, void *),
			 void *arg)
{
	int ret;
	char buf[JSON_BUFLEN+1];
	json_t *json = NULL;
	json_error_t json_error;
	size_t length = 0;
	size_t position = 0;
	int stop = 0;
	int err = 0;
	char *echo_reply = "{\"id\":\"echo\",\"result\":[],\"error\":null}";
	size_t echo_reply_len = strlen(echo_reply);

	int sfd = ovsdb_socket(conf);
	if (sfd < 0) {
		ret = sfd;
		goto out;
	}

	/* Request monitoring */
	ret = snprintf(buf, JSON_BUFLEN + 1, "{\"id\":0,\"method\":\"monitor\",\"params\":[\"%s\",null,{\"%s\":[{\"select\":{\"modify\":%s,\"initial\":%s,\"insert\":%s,\"delete\":%s}}]}]}",
                       conf->ovsdb_database, table, BOOL_TO_STR(modify),
		       BOOL_TO_STR(initial), BOOL_TO_STR(insert), BOOL_TO_STR(delete));
	if (ret < 0) {
		fprintf(stderr, "%s: snprintf to create monitoring command failed\n", __func__);
		goto close_sfd;
	}
	if ((ret = send(sfd, buf, ret, 0)) <= 0) {
		perror("Cannot send monitoring command");
		goto close_sfd;
	}

	/* Handle ovsdb monitor reply and updates */
	while (!stop && (ret = recv(sfd, buf + length, JSON_BUFLEN - length, 0)) > 0) { // TODO Assumes jsons of less than JSON_BUFLEN bytes

		length += ret;
		position = 0;
		while(!stop && position < length - 1 && (json = json_loadb(buf + position, length - position, JSON_DISABLE_EOF_CHECK, &json_error))) {

			position += json_error.position;

			if (!parse_ovsdb_echo(json)) {
				if ((err = send(sfd, echo_reply, echo_reply_len, 0)) < 0) {
					perror("Cannot send an echo reply");
				}
			} else {
				if (json_is_integer(json_object_get(json, "id"))) {
					stop = parse_ovsdb_monitor_reply(json, table, callback, arg);
				} else {
					stop = parse_ovsdb_update(json, table, callback, arg);
				}
				json_decref(json);
			}
		}
		if (!json) /* The full json is not yet in the buffer => wait for it */
			memcpy(buf, buf + position, length - position);
		else
			length = 0;
	}

	if (ret < 0) {
		perror("recv() from ovsdb_monitor() failed");
	}

close_sfd:
	close(sfd);
out:
	return ret;
}

struct trans_read_args {
	int sfd;
	struct queue_thread *jsons_received;
};

struct json_node {
	struct llnode node;
	struct json_t *json;
};

struct srdb_transact_reply {
	struct llnode node;
	int error;
	int count;
	char uuid[SLEN + 1];
};

static void *ovsdb_transaction_read(void *arg)
{
	struct trans_read_args *args = arg;
	int sfd = args->sfd;
	struct queue_thread *jsons_received = args->jsons_received;
	char buf[JSON_BUFLEN + 1];
	int stop = 0, ret = 0;
	int length = 0;
	int position = 0;
	json_t *json = NULL;
	json_error_t json_error;

	while (!stop && (ret = recv(sfd, buf + length, JSON_BUFLEN - length, 0)) > 0) { // TODO Assumes jsons of less than JSON_BUFLEN bytes

		length += ret;
		position = 0;
		while(position < length - 1 && (json = json_loadb(buf + position, length - position, JSON_DISABLE_EOF_CHECK, &json_error))) {

			position += json_error.position;
			if (json) {
				char *debug_json_str = json_dumps(json, 0); // TODO
				fprintf(stderr, "%s: JSON read ! - json = %s\n",__func__, debug_json_str); // TODO
				free(debug_json_str); // TODO

				struct json_node *node = calloc(1, sizeof(*node));
				node->json = json;
				stop = mqueue_append(jsons_received, (struct llnode *) node);
			}
		}
		if (!json) /* The full json is not yet in the buffer => wait for it */
			memcpy(buf, buf + position, length - position);
		else
			length = 0;
	}

	printf("%s: End of READ transaction thread with error code %d\n", __func__, ret); // TODO

	/* If the user closed the queue with a lower number of thread_consumers */
	mqueue_close(jsons_received, 1, 2);

	return NULL;
}

int srdb_transaction(const struct ovsdb_config *conf, struct queue_thread *input,
		     struct queue_thread *output)
{
	/* TODO A possible optimisation is to ignore the answer => not enqueue it to output */
	/* TODO Perhaps using an arraylist here would be better */
	int ret = 0;
	struct json_node *json_node;
	int transact_id = 0;
	char *echo_reply = "{\"id\":\"echo\",\"result\":[],\"error\":null}";
	char json_buf[JSON_BUFLEN+1];
	size_t echo_reply_len = strlen(echo_reply);

	int sfd = ovsdb_socket(conf);
	if (sfd < 0) {
		ret = sfd;
		goto out;
	}

	/* Start a thread that will read the socket and enqueue replies */
	pthread_t read_thread;
	struct trans_read_args args = {
		.sfd = sfd,
		.jsons_received = input
	};
	pthread_create(&read_thread, NULL, ovsdb_transaction_read, &args);

	mqueue_walk_dequeue(input, json_node, struct json_node *) {
		json_t *json = json_node->json;
		json_t *method = json_object_get(json, "method");
		json_t *error = json_object_get(json, "error");

		char *debug_json_str = json_dumps(json, 0); // TODO
		fprintf(stderr, "%s: loop start - json = %s\n",__func__, debug_json_str); // TODO
		free(debug_json_str); // TODO

		if (!json) {
			fprintf(stderr, "Null json given\n");
			free(json_node);
			continue;
		} else if (!method && error) {

			fprintf(stderr, "%s: Receive transaction results\n",__func__); // TODO

			/* Transaction result */
			struct srdb_transact_reply *transact_result = calloc(1, sizeof(*transact_result));
			transact_result->count = -1;
			if (!json_is_null(error)) {
				char *error_str = json_dumps(error, 0);
				fprintf(stderr, "Non-null transaction result: %s", error_str);
				free(error_str);
				transact_result->error = 1;
			} else {
				fprintf(stderr, "%s: HEEERE\n",__func__); // TODO
				json_t *result = json_array_get(json_object_get(json, "result"), 0);
				fprintf(stderr, "%s: HEEERE 2 - result %p\n",__func__, result); // TODO
				json_t *count = json_object_get(result, "count");
				fprintf(stderr, "%s: HEEERE 3 - count %p\n",__func__, count); // TODO
				if (!count) {
					fprintf(stderr, "%s: HEEERE 4\n",__func__); // TODO
					json_t *uuid = json_array_get(json_object_get(result, "uuid"), 1);
					fprintf(stderr, "%s: HEEERE 5 uuid = %p\n",__func__, uuid); // TODO
					strncpy(transact_result->uuid, json_string_value(uuid), SLEN + 1);
					fprintf(stderr, "%s: HEEERE 6\n",__func__); // TODO
				} else {
					fprintf(stderr, "%s: HEEERE 7\n",__func__); // TODO
					transact_result->count = json_integer_value(count);
					fprintf(stderr, "%s: HEEERE 8\n",__func__); // TODO
				}
			}
			fprintf(stderr, "%s: Receive transaction results - before appending error = %d - address %p\n",__func__, transact_result->error, transact_result); // TODO
			mqueue_append(output, (struct llnode *) transact_result);
			fprintf(stderr, "%s: Receive transaction results - before appending error = %d - address %p\n",__func__, transact_result->error, transact_result); // TODO

		} else if (method && !strcmp(json_string_value(method), "transact")) {

			fprintf(stderr, "%s: Send transaction request\n",__func__); // TODO

			/* Transaction request */
			json_object_set_new(json, "id", json_integer(transact_id));
			transact_id++;

			ret = (int) json_dumpb(json, json_buf, JSON_BUFLEN, JSON_COMPACT);
			if (!ret) {
				ret = -1;
				fprintf(stderr, "%s: Cannot dump the json\n", __func__);
				goto end_loop;
			}

			if ((ret = send(sfd, json_buf, ret, 0)) <= 0) {
				perror("Cannot send transaction command");
				goto end_loop;
			}
		} else if (method && !strcmp(json_string_value(method), "echo")) {

			fprintf(stderr, "%s: Echo send\n",__func__); // TODO

			/* Echo request */
			if ((ret = send(sfd, echo_reply, echo_reply_len, 0)) < 0) {
				perror("Cannot send an echo reply");
			}
		} else {
			char *unknown_json_str = json_dumps(json, 0);
			fprintf(stderr, "%s: Could not parse json = %s\n",__func__, unknown_json_str);
			free(unknown_json_str);
		}
end_loop:
		json_decref(json);
		free(json_node);
		fprintf(stderr, "%s: loop end\n",__func__); // TODO
	}

	if (ret < 0) {
		perror("srdb_transaction() failed");
	}

	printf("%s: End of transaction thread with error code %d\n", __func__, ret); // TODO
	fflush(stdout); // TODO

	/* These actions trigger the end of the reader thread */
	close(sfd);
	mqueue_close(input, 1, 2);

	pthread_join(read_thread, NULL);
out:
	return ret;
}

static int ovsdb_update(const struct ovsdb_config *conf, const char *table,
			const char *uuid, json_t *fields, struct queue_thread *input,
			struct queue_thread *output)
{
	/* TODO Allow several updates at the same time */
	int ret = 0;
	char cmd[JSON_BUFLEN+1];

	char *str_fields = json_dumps(fields, 0);
	if (!str_fields) {
		fprintf(stderr, "Invalid json\n");
		return -1;
	}

	snprintf(cmd, JSON_BUFLEN, "{\"method\":\"transact\",\"params\":[\"%s\",{\"row\":%s,\"table\":\"%s\",\"op\":\"update\",\"where\":[[\"_uuid\",\"==\",[\"uuid\",\"%s\"]]]}]}",
		 conf->ovsdb_database, str_fields, table, uuid);
	free(str_fields);

	json_t *update = json_loads(cmd, 0, NULL);
	if (!update) {
		fprintf(stderr, "Invalid transaction\n");
		return -1;
	}

	struct json_node *node = calloc(1, sizeof(*node));
	node->json = update;
	ret = mqueue_append(input, (struct llnode *) node);
	if (ret) {
		free(node);
		json_decref(update);
		return -1;
	}

	/* Wait for transaction to finish (assuming one transaction thread) */
	struct srdb_transact_reply *reply = (struct srdb_transact_reply *) mqueue_dequeue(output);
	if (!reply)
		return -1;
	ret = reply->error ? reply->error : reply->count;
	free(reply);

	return ret;
}

static int ovsdb_insert(const struct ovsdb_config *conf, const char *table,
			json_t *fields, char *uuid, struct queue_thread *input,
			struct queue_thread *output)
{
	/* TODO Allow several insertions at the same time */
	int ret = 0;
	char cmd[JSON_BUFLEN+1];

	char *str_fields = json_dumps(fields, 0);
	if (!str_fields) {
		fprintf(stderr, "Invalid json\n");
		return -1;
	}

	snprintf(cmd, JSON_BUFLEN, "{\"method\":\"transact\",\"params\":[\"%s\",{\"row\":%s,\"table\":\"%s\",\"op\":\"insert\"}]}",
		 conf->ovsdb_database, str_fields, table);
	free(str_fields);

	json_t *insert = json_loads(cmd, 0, NULL);
	if (!insert) {
		fprintf(stderr, "Invalid transaction\n");
		return -1;
	}

	struct json_node *node = calloc(1, sizeof(*node));
	node->json = insert;
	ret = mqueue_append(input, (struct llnode *) node);
	if (ret) {
		free(node);
		json_decref(insert);
		return -1;
	}

	/* Wait for transaction to finish (assuming one transaction thread) */
	struct srdb_transact_reply *reply = (struct srdb_transact_reply *) mqueue_dequeue(output);
	if (!reply)
		return -1;

	ret = reply->error;
	fprintf(stderr, "%s: return value = %d - address %p\n", __func__, ret, reply);
	if (!ret && uuid)
		strncpy(uuid, reply->uuid, SLEN + 1);

	free(reply);
	return ret;
}

static int find_desc_fromname(struct srdb_descriptor *desc, const char *name)
{
	int i;

	for (i = 0; desc[i].name; i++) {
		if (!strcmp(desc[i].name, name))
			return i;
	}

	return -1;
}

static void fill_srdb_entry(struct srdb_descriptor *desc,
			    struct srdb_entry *entry, const char *uuid, json_t *line_json)
{
	void *data;
	int i;
	json_t *column_value;

	for (i = 0; desc[i].name; i++) {
		if (!strcmp(desc[i].name, "row")) {
			strncpy(entry->row, uuid, desc[i].maxlen);
			continue;
		}

		column_value = json_object_get(line_json, desc[i].name);
		if (!column_value) {
			if (strcmp(desc[i].name, "action"))
				fprintf(stderr, "The column %s cannot be found !\n", desc[i].name);
			continue;
		}
		if (!strcmp(desc[i].name, "_version")) {
			column_value = json_object_get(line_json, "_version");
			column_value = json_array_get(column_value, 1);
		}

		data = (unsigned char *)entry + desc[i].offset;

		switch (desc[i].type) {
		case SRDB_STR:
			if (!json_is_string(column_value))
				fprintf(stderr, "String is expected for %s but the json is not of that type\n", desc[i].name);
			else
				strncpy((char *)data, json_string_value(column_value), desc[i].maxlen);
			break;
		case SRDB_INT:
			if (!json_is_integer(column_value))
				fprintf(stderr, "Integer is expected for %s but the json is not of that type\n", desc[i].name);
			else
				*(int *)data = (int) ntohl((long) json_integer_value(column_value));
			break;
		case SRDB_VARSTR:
			if (!json_is_string(column_value))
				fprintf(stderr, "String is expected for %s but the json is not of that type\n", desc[i].name);
			else
				*(char **)data = strndup(json_string_value(column_value), desc[i].maxlen);
			break;
		}
	}
}

void free_srdb_entry(struct srdb_descriptor *desc,
		     struct srdb_entry *entry)
{
	struct srdb_descriptor *tmp;

	for (tmp = desc; tmp->name; tmp++) {
		void *data = (unsigned char *)entry + tmp->offset;

		if (tmp->type == SRDB_VARSTR)
			free(*(char **)data);
	}

	free(entry);
}

#define SRDB_BUILTIN_ENTRIES()					\
	{							\
		.name	= "row",				\
		.type	= SRDB_STR,				\
		.maxlen	= SLEN,					\
		.builtin = true,				\
		.offset	= offsetof(struct srdb_entry, row),	\
	},							\
	{							\
		.name	= "action",				\
		.type	= SRDB_STR,				\
		.maxlen	= SLEN,					\
		.builtin = true,				\
		.offset	= offsetof(struct srdb_entry, action),	\
	},							\
	{							\
		.name	= "_version",				\
		.type	= SRDB_STR,				\
		.maxlen	= SLEN,					\
		.builtin = true,				\
		.offset = offsetof(struct srdb_entry, version),	\
	}

#define OFFSET_ROUTERIDS(NAME)	offsetof(struct srdb_router_entry, NAME)
static struct srdb_descriptor routerids_desc_tmpl[] = {
	SRDB_BUILTIN_ENTRIES(),

	{
		.name	= "router",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_ROUTERIDS(router),
	},
	{
		.name	= NULL,
	},
};

#define OFFSET_FLOWREQ(NAME)	offsetof(struct srdb_flowreq_entry, NAME)
static struct srdb_descriptor flowreq_desc_tmpl[] = {
	SRDB_BUILTIN_ENTRIES(),

	{
		.name	= "req_id",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWREQ(request_id),
	},
	{
		.name	= "destination",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWREQ(destination),
	},
	{
		.name	= "dstaddr",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWREQ(dstaddr),
	},
	{
		.name	= "source",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWREQ(source),
	},
	{
		.name	= "bandwidth",
		.type	= SRDB_INT,
		.maxlen	= sizeof(int),
		.offset	= OFFSET_FLOWREQ(bandwidth),
	},
	{
		.name	= "delay",
		.type	= SRDB_INT,
		.maxlen	= sizeof(int),
		.offset	= OFFSET_FLOWREQ(delay),
	},
	{
		.name	= "router",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset = OFFSET_FLOWREQ(router),
	},
	{
		.name	= "proxy",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWREQ(proxy),
	},
	{
		.name	= "status",
		.type	= SRDB_INT,
		.maxlen	= sizeof(int),
		.offset	= OFFSET_FLOWREQ(status),
	},
	{
		.name	= NULL,
	},
};

#define OFFSET_FLOWSTATE(NAME)	offsetof(struct srdb_flow_entry, NAME)
static struct srdb_descriptor flowstate_desc_tmpl[] = {
	SRDB_BUILTIN_ENTRIES(),

	{
		.name	= "destination",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWSTATE(destination),
	},
	{
		.name	= "dstaddr",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWSTATE(dstaddr),
	},
	{
		.name	= "bsid",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWSTATE(bsid),
	},
	{
		.name	= "segments",
		.type	= SRDB_VARSTR,
		.maxlen	= BUFLEN,
		.offset	= OFFSET_FLOWSTATE(segments),
	},
	{
		.name	= "bandwidth",
		.type	= SRDB_INT,
		.offset	= OFFSET_FLOWSTATE(bandwidth),
	},
	{
		.name	= "delay",
		.type	= SRDB_INT,
		.offset	= OFFSET_FLOWSTATE(delay),
	},
	{
		.name	= "policing",
		.type	= SRDB_INT,
		.offset	= OFFSET_FLOWSTATE(policing),
	},
	{
		.name	= "source",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWSTATE(source),
	},
	{
		.name	= "router",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWSTATE(router),
	},
	{
		.name	= "proxy",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWSTATE(proxy),
	},
	{
		.name	= "interface",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWSTATE(interface),
	},
	{
		.name	= "reverseFlow",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWSTATE(reverse_flow_uuid),
	},
	{
		.name	= "request",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWSTATE(request_id),
	},
	{
		.name	= "ttl",
		.type	= SRDB_INT,
		.offset	= OFFSET_FLOWSTATE(ttl),
	},
	{
		.name	= "idle",
		.type	= SRDB_INT,
		.offset	= OFFSET_FLOWSTATE(idle),
	},
	{
		.name	= "timestamp",
		.type	= SRDB_INT,
		.offset	= OFFSET_FLOWSTATE(timestamp),
	},
	{
		.name	= "status",
		.type	= SRDB_INT,
		.offset	= OFFSET_FLOWSTATE(status),
	},
	{
		.name	= NULL,
	},
};

#define OFFSET_LINKSTATE(NAME)	offsetof(struct srdb_linkstate_entry, NAME)
static struct srdb_descriptor linkstate_desc_tmpl[] = {
	SRDB_BUILTIN_ENTRIES(),

	{
		.name	= "name1",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_LINKSTATE(name1),
	},
	{
		.name	= "addr1",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_LINKSTATE(addr1),
	},
	{
		.name	= "name2",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_LINKSTATE(name2),
	},
	{
		.name	= "addr2",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_LINKSTATE(addr2),
	},
	{
		.name	= "metric",
		.type	= SRDB_INT,
		.offset	= OFFSET_LINKSTATE(metric),
	},
	{
		.name	= "bw",
		.type	= SRDB_INT,
		.offset	= OFFSET_LINKSTATE(bw),
	},
	{
		.name	= "ava_bw",
		.type	= SRDB_INT,
		.offset	= OFFSET_LINKSTATE(ava_bw),
	},
	{
		.name	= "delay",
		.type	= SRDB_INT,
		.offset	= OFFSET_LINKSTATE(delay),
	},
	{
		.name	= NULL,
	},
};

#define OFFSET_NODESTATE(NAME)	offsetof(struct srdb_nodestate_entry, NAME)
static struct srdb_descriptor nodestate_desc_tmpl[] = {
	SRDB_BUILTIN_ENTRIES(),

	{
		.name	= "name",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_NODESTATE(name),
	},
	{
		.name	= "addr",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_NODESTATE(addr),
	},
	{
		.name	= "prefix",
		.type	= SRDB_VARSTR,
		.maxlen	= BUFLEN,
		.offset	= OFFSET_NODESTATE(prefix),
	},
	{
		.name	= "pbsid",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_NODESTATE(pbsid),
	},
	{
		.name	= NULL,
	},
};

static struct srdb_table srdb_tables[] = {
	{
		.name		= "RouterIds",
		.entry_size	= sizeof(struct srdb_router_entry),
		.desc_tmpl	= routerids_desc_tmpl,
		.desc_size	= sizeof(routerids_desc_tmpl),
	},
	{
		.name		= "FlowReq",
		.entry_size	= sizeof(struct srdb_flowreq_entry),
		.desc_tmpl	= flowreq_desc_tmpl,
		.desc_size	= sizeof(flowreq_desc_tmpl),
	},
	{
		.name		= "FlowState",
		.entry_size	= sizeof(struct srdb_flow_entry),
		.desc_tmpl	= flowstate_desc_tmpl,
		.desc_size	= sizeof(flowstate_desc_tmpl),
	},
	{
		.name		= "LinkState",
		.entry_size	= sizeof(struct srdb_linkstate_entry),
		.desc_tmpl	= linkstate_desc_tmpl,
		.desc_size	= sizeof(linkstate_desc_tmpl),
	},
	{
		.name		= "NodeState",
		.entry_size	= sizeof(struct srdb_nodestate_entry),
		.desc_tmpl	= nodestate_desc_tmpl,
		.desc_size	= sizeof(nodestate_desc_tmpl),
	},
	{
		.name		= NULL,
	},
};

struct srdb_table *srdb_get_tables(void)
{
	struct srdb_table *tbl;
	unsigned int i;

	tbl = memdup(srdb_tables, sizeof(srdb_tables));
	if (!tbl)
		return NULL;

	for (i = 0; i < sizeof(srdb_tables) / sizeof(struct srdb_table); i++) {
		if (tbl[i].name)
			tbl[i].desc = memdup(tbl[i].desc_tmpl, tbl[i].desc_size);
	}

	return tbl;
}

void srdb_free_tables(struct srdb_table *tbl)
{
	unsigned int i;

	for (i = 0; i < sizeof(srdb_tables) / sizeof(struct srdb_table); i++) {
		if (tbl[i].name)
			free(tbl[i].desc);
	}

	free(tbl);
}

struct srdb_table *srdb_table_by_name(struct srdb_table *tables,
				      const char *name)
{
	struct srdb_table *tbl;

	for (tbl = tables; tbl->name; tbl++) {
		if (!strcmp(tbl->name, name))
			return tbl;
	}

	return NULL;
}

static int srdb_read(const char *uuid, json_t *json, int initial, void *arg)
{
	int idx;
	struct srdb_table *tbl = arg;
	struct srdb_entry *entry = NULL;
	char *action;
	json_t *new = NULL;
	json_t *old = NULL;
	int ret = 0;

	gettimeofday(&tbl->last_read, NULL);

	if (!uuid || !json)
		return -1;

	new = json_object_get(json, "new");
	old = json_object_get(json, "old");

	char *json_str = json_dumps(json, 0); // TODO
	printf("\n%s: json = %s - old %d - new %d - initial %d\n" ,__func__, json_str, !!old, !!new, initial); // TODO
	free(json_str); // TODO

	idx = find_desc_fromname(tbl->desc, "action");
	if (idx < 0) {
		pr_err("field `action' not present in row.");
		free_srdb_entry(tbl->desc, entry);
		ret = -1;
		goto out;
	}

	if (new) {
		entry = calloc(1, tbl->entry_size);
		action = (char *)entry + tbl->desc[idx].offset;
		if (!entry) {
			ret = -1;
			goto out;
		}
	}
	if (old) {
		tbl->update_entry = calloc(1, tbl->entry_size);
		if (!tbl->update_entry) {
			ret = -1;
			goto free_new;
		}
	}


	if (new) {
		sprintf(action, "%s", initial ? "initial" : "insert");
		fill_srdb_entry(tbl->desc, entry, uuid, new);

		printf("%s: entry uuid %s\n" ,__func__, entry->row); // TODO
		printf("%s: entry action %s\n" ,__func__, action); // TODO
		printf("%s: entry version %s\n" ,__func__, entry->version); // TODO

		if (tbl->read)
			ret = tbl->read(entry);
		if (!tbl->delayed_free)
			free_srdb_entry(tbl->desc, entry);
	} else if (new && old) { /* TODO fix for delayed free / MT */
		strcpy(action, "update");
		fill_srdb_entry(tbl->desc, entry, uuid, new);
		memcpy(entry, tbl->update_entry, tbl->entry_size);
		fill_srdb_entry(tbl->desc, tbl->update_entry, uuid, old);

		printf("%s: entry uuid %s\n" ,__func__, entry->row); // TODO
		printf("%s: entry action %s\n" ,__func__, action); // TODO
		printf("%s: entry version %s\n" ,__func__, entry->version); // TODO

		printf("%s: old entry uuid %s\n" ,__func__, tbl->update_entry->row); // TODO
		printf("%s: old entry action %s\n" ,__func__, action); // TODO
		printf("%s: old entry version %s\n" ,__func__, tbl->update_entry->version); // TODO

		if (tbl->read_update)
			ret = tbl->read_update(tbl->update_entry, entry);
		free_srdb_entry(tbl->desc, tbl->update_entry);
		free_srdb_entry(tbl->desc, entry);
		tbl->update_entry = NULL;
	} else if (old) {
		action = (char *)(tbl->update_entry) + tbl->desc[idx].offset;
		strcpy(action, "delete");
		fill_srdb_entry(tbl->desc, tbl->update_entry, uuid, old);
		if (tbl->read_delete)
			ret = tbl->read_delete(tbl->update_entry);
		free_srdb_entry(tbl->desc, tbl->update_entry);
		tbl->update_entry = NULL;
	} else {
		free_srdb_entry(tbl->desc, entry);
		pr_err("unknown action type `%s'.", action);
		ret = -1;
	}

out:
	return ret;
free_new:
	if (entry)
		free_srdb_entry(tbl->desc, entry);
	goto out;
}

int srdb_monitor(struct srdb *srdb, struct srdb_table *tbl, int modify, int initial, int insert, int delete)
{
	int ret;

	ret = ovsdb_monitor(&srdb->conf, tbl->name, modify, initial, insert, delete, srdb_read, tbl);

	return ret;
}

static int write_desc_data(json_t *row, const struct srdb_descriptor *desc,
			   struct srdb_entry *entry)
{
	int wr = -1;
	void *data;

	data = (unsigned char *)entry + desc->offset;

	switch (desc->type) {
	case SRDB_STR:
		wr = json_object_set_new(row, desc->name, json_string((char *)data));
		break;
	case SRDB_INT:
		wr = json_object_set_new(row, desc->name, json_integer(*(int *)data));
		break;
	case SRDB_VARSTR:
		wr = json_object_set_new(row, desc->name, json_string(*(char **)data));
		break;
	}

	return wr;
}

int srdb_update(struct srdb *srdb, struct srdb_table *tbl,
		struct srdb_entry *entry, const char *fieldname,
		struct queue_thread *input, struct queue_thread *output)
{
	const struct srdb_descriptor *desc;
	int ret, idx;

	idx = find_desc_fromname(tbl->desc, fieldname);
	if (idx < 0)
		return -1;

	desc = &tbl->desc[idx];

	json_t *row = json_object();
	ret = write_desc_data(row, desc, entry);
	if (ret < 0)
		goto free_json;

	ret = ovsdb_update(&srdb->conf, tbl->name, entry->row, row, input, output);
free_json:
	json_decref(row);
	return ret;
}

int srdb_insert(struct srdb *srdb, struct srdb_table *tbl,
		struct srdb_entry *entry, char *uuid, struct queue_thread *input,
		struct queue_thread *output)
{
	const struct srdb_descriptor *tmp;
	int ret;

	json_t *row = json_object();

	for (tmp = tbl->desc; tmp->name; tmp++) {
		if (!tmp->builtin) {
			ret = write_desc_data(row, tmp, entry);
			if (ret < 0)
				goto free_json;
		}
	}

	ret = ovsdb_insert(&srdb->conf, tbl->name, row, uuid, input, output);
free_json:
	json_decref(row);
	return ret;
}

struct srdb *srdb_new(const struct ovsdb_config *conf)
{
	struct srdb *srdb;

	srdb = malloc(sizeof(*srdb));
	if (!srdb)
		return NULL;

	srdb->tables = srdb_get_tables();
	if (!srdb->tables) {
		free(srdb);
		return NULL;
	}

	memcpy(&srdb->conf, conf, sizeof(*conf));

	return srdb;
}

void srdb_destroy(struct srdb *srdb)
{
	srdb_free_tables(srdb->tables);
	free(srdb);
}

void srdb_set_read_cb(struct srdb *srdb, const char *table,
		      int (*cb)(struct srdb_entry *))
{
	struct srdb_table *tbl;

	tbl = srdb_table_by_name(srdb->tables, table);
	if (!tbl)
		return;

	tbl->read = cb;
}
