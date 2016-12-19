#ifndef _SRDB_H
#define _SRDB_H

#include <stdbool.h>
#include <netinet/in.h>

#define SLEN	127

enum srdb_type {
	SRDB_STR,
	SRDB_INT,
};

struct srdb_descriptor {
	const char *name;
	enum srdb_type type;
	void *data;
	int index;
	size_t maxlen;
	bool builtin;
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
	void (*fill)(struct srdb_descriptor *, struct srdb_entry *);
	void (*read)(struct srdb_entry *);
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

struct srdb_flow_entry {
	struct srdb_entry entry;
	char destination[SLEN + 1];
	char bsid[SLEN + 1];
	char *segments;
	int __nsegs;
	int bandwidth;
	int delay;
	int policing;
	char source[SLEN + 1];
	char router[SLEN + 1];
	char interface[SLEN + 1];
	int reverse;
	char reverse_flow_uuid[SLEN + 1];
	char request_uuid[SLEN + 1];
	int ttl;
	int idle;
};

struct srdb_flowreq_entry {
	struct srdb_entry entry;
	char destination[SLEN + 1];
	char dstaddr[SLEN + 1];
	char source[SLEN + 1];
	int bandwidth;
	int delay;
	char router[SLEN + 1];
	int status;
};

enum flowreq_status {
	STATUS_PENDING = 0,
	STATUS_ALLOWED = 1,
	STATUS_DENIED = 2,
	STATUS_UNAVAILABLE = 3,
	STATUS_ERROR = 4,
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

/* internal structures */

struct prefix {
	struct in6_addr addr;
	int len;
};
	
struct router {
	char name[SLEN + 1];
	struct in6_addr addr;
	struct prefix pbsid;
	struct hashmap *flows;
	struct node *node;
};

struct link {
	struct in6_addr local;
	struct in6_addr remote;
	uint32_t bw;
	uint32_t ava_bw;
	uint32_t delay;
};

struct flow {
	struct in6_addr bsid;
	char src[SLEN + 1];
	char dst[SLEN + 1];
	struct node *srcnode;
	struct node *dstnode;
	struct arraylist *segs;
	uint32_t bw;
	uint32_t delay;
	uint32_t ttl;
	uint32_t idle;
};

int srdb_monitor(struct srdb *srdb, struct srdb_table *tbl,
		 const char *columns);
int srdb_update(struct srdb *srdb, struct srdb_table *tbl,
		struct srdb_entry *entry, struct srdb_descriptor *desc);
int srdb_insert(struct srdb *srdb, struct srdb_table *tbl,
		struct srdb_entry *entry);

struct srdb_table *srdb_get_tables(void);
void srdb_free_tables(struct srdb_table *tbl);
struct srdb_table *srdb_table_by_name(struct srdb_table *tables,
				      const char *name);
struct srdb *srdb_new(const struct ovsdb_config *conf);
void srdb_destroy(struct srdb *srdb);

#endif
