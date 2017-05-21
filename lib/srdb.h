#ifndef _SRDB_H
#define _SRDB_H

#include <string.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <jansson.h>

#include "sbuf.h"

#define SLEN	127
#define SLEN_LIST	7 * SLEN

#define ENTRY_MASK(x) (1 << (x))
#define ENTRY_MASK_ALL(last) (0xffffffff & ((ENTRY_MASK((last) + 1)) - 1))

enum srdb_type {
	SRDB_STR,
	SRDB_INT,
	SRDB_VARSTR,
};

struct srdb_descriptor {
	const char *name;
	enum srdb_type type;
	unsigned int index;
	size_t maxlen;
	bool builtin;
	off_t offset;
};

struct srdb_entry {
	char row[SLEN + 1];
	char version[SLEN + 1];
};

struct srdb_table {
	const char *name;
	const struct srdb_descriptor *desc_tmpl;
	struct srdb_descriptor *desc;
	size_t desc_size;
	size_t entry_size;
	int (*read)(struct srdb_entry *);
	int (*read_update)(struct srdb_entry *, struct srdb_entry *,
			   unsigned int);
	int (*read_delete)(struct srdb_entry *);
	struct srdb_entry *update_entry;
	sem_t initial_read;
	bool delayed_free;
};

struct ovsdb_config {
	char ovsdb_client[SLEN + 1];
	char ovsdb_server[SLEN + 1];
	char ovsdb_database[SLEN + 1];
	int ntransacts;
};

struct transaction {
	json_t *json;
	struct sbuf *result;
};

#define OVSDB_UPDATE_FORMAT						\
	"{\"method\":\"transact\",\"params\":[\"%s\",{\"row\":%s,"	\
	"\"table\":\"%s\",\"op\":\"update\","				\
	"\"where\":[[\"_uuid\",\"==\",[\"uuid\",\"%s\"]]]}]}"

#define OVSDB_INSERT_FORMAT 						\
	"{\"method\":\"transact\",\"params\":[\"%s\",{\"row\":%s,"	\
	"\"table\":\"%s\",\"op\":\"insert\"}]}"

struct srdb {
	struct ovsdb_config *conf;
	struct srdb_table *tables;
	struct sbuf *transactions;
	pthread_t *tr_workers;
};

#define _row		entry.row
#define _version	entry.version

/* OVSDB tables description */

struct srdb_router_entry {
	struct srdb_entry entry;
	char router[SLEN + 1];
};

enum {
	RTE_ROUTER = 0,
};

#define RTE_LAST RTE_ROUTER
#define RTE_ALL ENTRY_MASK_ALL(RTE_LAST)

struct srdb_flow_entry {
	struct srdb_entry entry;
	char destination[SLEN + 1];
	char dstaddr[SLEN + 1];
	char *bsid;
	char *segments;
	int bandwidth;
	int delay;
	int policing;
	char source[SLEN + 1]; /* Name of the source */
	char *sourceIPs; /* List of source prefixes that can be used with a priority (e.g., "[[5,2001:abcd::,64],[-12,2001:beef::,64]]") */
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

/* flow entry fields */
enum {
	FE_DESTINATION = 0,
	FE_DSTADDR,
	FE_BSID,
	FE_SEGMENTS,
	FE_BANDWIDTH,
	FE_DELAY,
	FE_POLICING,
	FE_SOURCE,
	FE_SOURCEIPS,
	FE_ROUTER,
	FE_PROXY,
	FE_INTERFACE,
	FE_RF_UUID,
	FE_REQID,
	FE_TTL,
	FE_IDLE,
	FE_TS,
	FE_STATUS,
};

#define FE_LAST	FE_STATUS
#define FE_ALL ENTRY_MASK_ALL(FE_LAST)

enum flow_status {
	FLOW_STATUS_ACTIVE	= 0,
	FLOW_STATUS_RUNNING	= 1,
	FLOW_STATUS_EXPIRED	= 2,
	FLOW_STATUS_ORPHAN	= 3,
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

enum {
	FREQ_REQID = 0,
	FREQ_DESTINATION,
	FREQ_DSTADDR,
	FREQ_SOURCE,
	FREQ_BANDWIDTH,
	FREQ_DELAY,
	FREQ_ROUTER,
	FREQ_PROXY,
	FREQ_STATUS,
};

#define FREQ_LAST FREQ_STATUS
#define FREQ_ALL ENTRY_MASK_ALL(FREQ_LAST)

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
	char addr1[SLEN + 1]; /* List of prefixes on the prefixes available */
	char name2[SLEN + 1];
	char addr2[SLEN + 1];
	int metric;
	int bw;
	int ava_bw;
	int delay;
};

enum {
	LS_NAME1 = 0,
	LS_ADDR1,
	LS_NAME2,
	LS_ADDR2,
	LS_METRIC,
	LS_BW,
	LS_AVA_BW,
	LS_DELAY,
};

#define LS_LAST LS_DELAY
#define LS_ALL ENTRY_MASK_ALL(LS_LAST)

struct srdb_nodestate_entry {
	struct srdb_entry entry;
	char name[SLEN + 1];
	char addr[SLEN + 1];
	char *prefix;
	char pbsid[SLEN + 1];
};

enum {
	NODE_NAME = 0,
	NODE_ADDR,
	NODE_PREFIX,
	NODE_PBSID,
};

#define NODE_LAST NODE_PBSID
#define NODE_ALL ENTRY_MASK_ALL(NODE_LAST)

struct srdb_update_transact {
	struct srdb *srdb;
	struct srdb_table *tbl;
	struct srdb_entry *entry;
	unsigned int index_mask;
	json_t *fields;
};

int srdb_monitor(struct srdb *srdb, struct srdb_table *tbl,
		int modify, int initial, int insert, int delete);
struct transaction *srdb_update(struct srdb *srdb, struct srdb_table *tbl,
				struct srdb_entry *entry,
				unsigned int index);
struct transaction *srdb_insert(struct srdb *srdb, struct srdb_table *tbl,
				struct srdb_entry *entry);

struct srdb_update_transact *srdb_update_prepare(struct srdb *srdb,
						 struct srdb_table *tbl,
						 struct srdb_entry *entry);
struct transaction *srdb_update_commit(struct srdb_update_transact *utr);
int srdb_update_sync(struct srdb *srdb, struct srdb_table *tbl,
		     struct srdb_entry *entry, unsigned int index,
		     int *count);
int srdb_update_result(struct transaction *tr, int *count);
int srdb_update_append(struct srdb_update_transact *utr, unsigned int index);
void srdb_update_append_mask(struct srdb_update_transact *tr,
			     unsigned int index_mask);
int srdb_insert_sync(struct srdb *srdb, struct srdb_table *tbl,
		     struct srdb_entry *entry, char *uuid);

struct transaction *create_transaction(json_t *json);
void free_transaction(struct transaction *tr);

struct srdb_table *srdb_get_tables(void);
void srdb_free_tables(struct srdb_table *tbl);
struct srdb_table *srdb_table_by_name(struct srdb_table *tables,
				      const char *name);
struct srdb *srdb_new(struct ovsdb_config *conf);
void srdb_destroy(struct srdb *srdb);
void srdb_set_read_cb(struct srdb *srdb, const char *table,
		      int (*cb)(struct srdb_entry *));
void free_srdb_entry(struct srdb_descriptor *desc,
 		     struct srdb_entry *entry);

#endif
