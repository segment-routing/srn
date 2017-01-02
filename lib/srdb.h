#ifndef _SRDB_H
#define _SRDB_H

#include <string.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
	void (*read)(struct srdb_entry *);
	void (*read_update)(struct srdb_entry *, struct srdb_entry *);
	struct srdb_entry *update_entry;
	struct timeval last_read;
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
	char router[SLEN + 1];
	char interface[SLEN + 1];
	char reverse_flow_uuid[SLEN + 1];
	char request_id[SLEN + 1];
	int ttl;
	int idle;
};

struct srdb_flowreq_entry {
	struct srdb_entry entry;
	char request_id[SLEN + 1];
	char destination[SLEN + 1];
	char dstaddr[SLEN + 1];
	char source[SLEN + 1];
	int bandwidth;
	int delay;
	char router[SLEN + 1];
	int status;
};

enum flowreq_status {
	STATUS_PENDING		= 0,
	STATUS_ALLOWED		= 1,
	STATUS_DENIED		= 2,
	STATUS_UNAVAILABLE	= 3,
	STATUS_ERROR		= 4,
	STATUS_NOROUTER		= 6,
	STATUS_NOPREFIX		= 7,
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
		 const char *columns);
int srdb_update(struct srdb *srdb, struct srdb_table *tbl,
		struct srdb_entry *entry, const char *fieldname);
int srdb_insert(struct srdb *srdb, struct srdb_table *tbl,
		struct srdb_entry *entry, char *uuid);

struct srdb_table *srdb_get_tables(void);
void srdb_free_tables(struct srdb_table *tbl);
struct srdb_table *srdb_table_by_name(struct srdb_table *tables,
				      const char *name);
struct srdb *srdb_new(const struct ovsdb_config *conf);
void srdb_destroy(struct srdb *srdb);
void srdb_set_read_cb(struct srdb *srdb, const char *table,
		      void (*cb)(struct srdb_entry *));

#endif
