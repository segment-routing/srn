#ifndef _SRDB_H
#define _SRDB_H

#include <string.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "linked_list.h"

#define SLEN	127

enum srdb_type {
	SRDB_STR,
	SRDB_INT,
	SRDB_VARSTR,
};

struct srdb_descriptor {
	const char *name;
	enum srdb_type type;
	int index;
	size_t maxlen;
	bool builtin;
	off_t offset;
};

struct srdb_entry {
	char row[SLEN + 1];
	char action[SLEN + 1];
	char version[SLEN + 1];
};

struct srdb_table {
	const char *name;
	const struct srdb_descriptor *desc_tmpl;
	struct srdb_descriptor *desc;
	size_t desc_size;
	size_t entry_size;
	int (*read)(struct srdb_entry *);
	int (*read_update)(struct srdb_entry *, struct srdb_entry *);
	int (*read_delete)(struct srdb_entry *);
	struct srdb_entry *update_entry;
	struct timeval last_read;
	bool delayed_free;
};

struct ovsdb_config {
	char ovsdb_client[SLEN + 1];
	char ovsdb_server[SLEN + 1];
	char ovsdb_database[SLEN + 1];
};

struct srdb {
	struct ovsdb_config conf;
	struct srdb_table *tables;
};

#define _row		entry.row
#define _action		entry.action
#define _version	entry.version

/* OVSDB tables description */

struct srdb_router_entry {
	struct srdb_entry entry;
	char router[SLEN + 1];
};

struct srdb_flow_entry {
	struct srdb_entry entry;
	char destination[SLEN + 1];
	char dstaddr[SLEN + 1];
	char bsid[SLEN + 1];
	char *segments;
	int bandwidth;
	int delay;
	int policing;
	char source[SLEN + 1];
	char router[SLEN + 1]; /* Name of the access router */
	char proxy[SLEN + 1]; /* Name of the DNS proxy that inserts the rule in the database */
	char interface[SLEN + 1];
	char reverse_flow_uuid[SLEN + 1];
	char request_id[SLEN + 1];
	int ttl;
	int idle;
	int timestamp;
	int status;
};

enum flow_status {
	FLOW_STATUS_ACTIVE	= 0,
	FLOW_STATUS_RUNNING	= 1,
	FLOW_STATUS_EXPIRED	= 2,
};

struct srdb_flowreq_entry {
	struct srdb_entry entry;
	char request_id[SLEN + 1];
	char destination[SLEN + 1];
	char dstaddr[SLEN + 1];
	char source[SLEN + 1];
	int bandwidth;
	int delay;
	char router[SLEN + 1]; /* Name of the access router */
	char proxy[SLEN + 1]; /* Name of the DNS proxy that inserts the rule in the database */
	int status;
};

enum flowreq_status {
	REQ_STATUS_PENDING	= 0,
	REQ_STATUS_ALLOWED	= 1,
	REQ_STATUS_DENIED	= 2,
	REQ_STATUS_UNAVAILABLE	= 3,
	REQ_STATUS_ERROR	= 4,
	REQ_STATUS_NOROUTER	= 6,
	REQ_STATUS_NOPREFIX	= 7,
};

struct srdb_linkstate_entry {
	struct srdb_entry entry;
	char name1[SLEN + 1];
	char addr1[SLEN + 1];
	char name2[SLEN + 1];
	char addr2[SLEN + 1];
	int metric;
	int bw;
	int ava_bw;
	int delay;
};

struct srdb_nodestate_entry {
	struct srdb_entry entry;
	char name[SLEN + 1];
	char addr[SLEN + 1];
	char *prefix;
	char pbsid[SLEN + 1];
};

int srdb_monitor(struct srdb *srdb, struct srdb_table *tbl,
		int modify, int initial, int insert, int delete);
int srdb_transaction(const struct ovsdb_config *conf,
		     struct queue_thread *input,
		     struct queue_thread *output);
int srdb_update(struct srdb *srdb, struct srdb_table *tbl,
		struct srdb_entry *entry, const char *fieldname,
		struct queue_thread *input, struct queue_thread *output);
int srdb_insert(struct srdb *srdb, struct srdb_table *tbl,
		struct srdb_entry *entry, char *uuid,
		struct queue_thread *input, struct queue_thread *output);

struct srdb_table *srdb_get_tables(void);
void srdb_free_tables(struct srdb_table *tbl);
struct srdb_table *srdb_table_by_name(struct srdb_table *tables,
				      const char *name);
struct srdb *srdb_new(const struct ovsdb_config *conf);
void srdb_destroy(struct srdb *srdb);
void srdb_set_read_cb(struct srdb *srdb, const char *table,
		      int (*cb)(struct srdb_entry *));
void free_srdb_entry(struct srdb_descriptor *desc,
 		     struct srdb_entry *entry);

#endif
