#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "srdb.h"
#include "misc.h"

#define BUFLEN 1024

static int ovsdb_monitor(const struct ovsdb_config *conf, const char *table,
			 const char *columns,
			 void (*callback)(const char *buf, void *), void *arg)
{
	char line[BUFLEN+1];
	char cmd[BUFLEN+1];
	FILE *fp;
	int ret;

	snprintf(cmd, BUFLEN,
		 "%s monitor '%s' '%s' '%s' '%s' -f csv 2>/dev/null",
		 conf->ovsdb_client, conf->ovsdb_server, conf->ovsdb_database,
		 table, columns);

	fp = popen(cmd, "r");
	if (!fp) {
		perror("popen");
		return -1;
	}

	while (fgets(line, BUFLEN, fp)) {
		strip_crlf(line);
		callback(line, arg);
	}

	ret = pclose(fp);
	if (ret < 0)
		perror("pclose");

	/* ret = 256 => server closed connection */

	return ret;
}

static int ovsdb_update(const struct ovsdb_config *conf, const char *table,
			const char *uuid, const char *fields)
{
	char line[BUFLEN];
	char cmd[BUFLEN];
	int ret = 0;
	FILE *fp;

	snprintf(cmd, BUFLEN, "%s transact '%s' '[\"%s\", {\"op\": \"update\", "
			   "\"table\": \"%s\", \"where\": [[\"_uuid\", \"==\","
			   " [\"uuid\", \"%s\"]]], \"row\": {%s}}]' "
			   "2>/dev/null", conf->ovsdb_client,
			   conf->ovsdb_server, conf->ovsdb_database, table,
			   uuid, fields);

	fp = popen(cmd, "r");
	if (!fp) {
		perror("popen");
		return -1;
	}

	while (fgets(line, BUFLEN, fp)) {
		strip_crlf(line);
		if (!strcmp(line, "[{\"count\":1}]"))
			ret = 0;
		else
			ret = -1;
		break;
	}

	if (pclose(fp) < 0)
		perror("pclose");

	return ret;
}

static int ovsdb_insert(const struct ovsdb_config *conf, const char *table,
			const char *fields, char *uuid)
{
	const char *_start_match = "[{\"uuid\":[\"uuid\",";
	char line[BUFLEN];
	char cmd[BUFLEN];
	int ret = 0;
	FILE *fp;

	snprintf(cmd, BUFLEN, "%s transact '%s' '[\"%s\", {\"op\": \"insert\", "
			      "\"table\": \"%s\", \"row\": {%s}}]' 2>/dev/null",
			      conf->ovsdb_client, conf->ovsdb_server,
			      conf->ovsdb_database, table, fields);

	fp = popen(cmd, "r");
	if (!fp) {
		perror("popen");
		return -1;
	}

	while (fgets(line, BUFLEN, fp)) {
		strip_crlf(line);
		if (!strncmp(line, _start_match, strlen(_start_match)))
			ret = 0;
		else
			ret = 1;
		break;
	}

	if (uuid && !ret)
		sscanf(line, "[{\"uuid\":[\"uuid\",\"%[a-z0-9-]\"]}]", uuid);

	if (pclose(fp) < 0)
		perror("close");

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

static int find_desc_fromidx(struct srdb_descriptor *desc, int idx)
{
	int i;

	for (i = 0; desc[i].name; i++) {
		if (desc[i].index == idx)
			return i;
	}

	return -1;
}

static void fill_srdb_index(struct srdb_descriptor *desc, char **vargs)
{
	int i, idx;

	for (i = 0; *vargs; vargs++, i++) {
		idx = find_desc_fromname(desc, *vargs);
		if (idx < 0)
			continue;
		desc[idx].index = i;
	}
}

static void fill_srdb_entry(struct srdb_descriptor *desc,
			    struct srdb_entry *entry, char **vargs)
{
	void *data;
	int i, idx;

	for (i = 0; *vargs; vargs++, i++) {
		idx = find_desc_fromidx(desc, i);
		if (idx < 0)
			continue;

		data = (unsigned char *)entry + desc[idx].offset;

		switch (desc[idx].type) {
		case SRDB_STR:
			strncpy((char *)data, *vargs, desc[idx].maxlen);
			break;
		case SRDB_INT:
			*(int *)data = strtol(*vargs, NULL, 10);
			break;
		case SRDB_VARSTR:
			*(char **)data = strndup(*vargs, desc[idx].maxlen);
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

static char *normalize_rowbuf(const char *buf)
{
	size_t n = 0;
	const char *s;
	char *buf2;

	for (s = buf; *s; s++) {
		if (*s != '"')
			n++;
	}

	buf2 = calloc(1, n+1);
	if (!buf2)
		return NULL;

	for (n = 0, s = buf; *s; s++) {
		if (*s != '"')
			buf2[n++] = *s;
	}

	return buf2;
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

static void srdb_read(const char *buf, void *arg)
{
	struct srdb_table *tbl = arg;
	struct srdb_entry *entry;
	char *action;
	char **vargs;
	char *buf2;
	int vargc;
	int idx;

	gettimeofday(&tbl->last_read, NULL);

	if (!buf || !*buf)
		return;

	buf2 = normalize_rowbuf(buf);
	if (!buf2)
		return;

	vargs = strsplit(buf2, &vargc, ',');
	if (!vargs) {
		free(buf2);
		return;
	}

	if (!strcmp(*vargs, "row")) {
		fill_srdb_index(tbl->desc, vargs);
		free(vargs);
		free(buf2);
		return;
	}

	entry = calloc(1, tbl->entry_size);
	if (!entry) {
		free(vargs);
		free(buf2);
		return;
	}

	fill_srdb_entry(tbl->desc, entry, vargs);

	free(vargs);
	free(buf2);

	idx = find_desc_fromname(tbl->desc, "action");

	if (idx < 0) {
		pr_err("field `action' not present in row.");
		free_srdb_entry(tbl->desc, entry);
		return;
	}

	action = (char *)entry + tbl->desc[idx].offset;

	if (!strcmp(action, "insert") || !strcmp(action, "initial")) {
		if (tbl->read)
			tbl->read(entry);
		if (!tbl->delayed_free)
			free_srdb_entry(tbl->desc, entry);
	} else if (!strcmp(action, "old")) {
		tbl->update_entry = entry;
	} else if (!strcmp(action, "new")) { /* TODO fix for delayed free / MT */
		if (tbl->read_update)
			tbl->read_update(tbl->update_entry, entry);
		free_srdb_entry(tbl->desc, tbl->update_entry);
		free_srdb_entry(tbl->desc, entry);
		tbl->update_entry = NULL;
	} else {
		free_srdb_entry(tbl->desc, entry);
		pr_err("unknown action type `%s'.", action);
	}
}

int srdb_monitor(struct srdb *srdb, struct srdb_table *tbl, const char *columns)
{
	int ret;

	ret = ovsdb_monitor(&srdb->conf, tbl->name, columns, srdb_read, tbl);

	return ret;
}

static int write_desc_data(char *buf, size_t size,
			   const struct srdb_descriptor *desc,
			   struct srdb_entry *entry)
{
	int wr = -1;
	void *data;

	data = (unsigned char *)entry + desc->offset;

	switch (desc->type) {
	case SRDB_STR:
		wr = snprintf(buf, size, "\"%s\": \"%s\"", desc->name,
			      (char *)data);
		break;
	case SRDB_INT:
		wr = snprintf(buf, size, "\"%s\": %d", desc->name,
			      *(int *)data);
		break;
	case SRDB_VARSTR:
		wr = snprintf(buf, size, "\"%s\": \"%s\"", desc->name,
			      *(char **)data);
		break;
	}

	return wr;
}

int srdb_update(struct srdb *srdb, struct srdb_table *tbl,
		struct srdb_entry *entry, const char *fieldname)
{
	const struct srdb_descriptor *desc;
	char field_update[SLEN + 1];
	int ret, idx;

	idx = find_desc_fromname(tbl->desc, fieldname);
	if (idx < 0)
		return -1;

	desc = &tbl->desc[idx];

	write_desc_data(field_update, SLEN, desc, entry);

	ret = ovsdb_update(&srdb->conf, tbl->name, entry->row, field_update);

	return ret;
}

int srdb_insert(struct srdb *srdb, struct srdb_table *tbl,
		struct srdb_entry *entry, char *uuid)
{
	const struct srdb_descriptor *tmp;
	char fields[BUFLEN + 1];
	char field[SLEN + 1];
	int ret;

	memset(fields, 0, BUFLEN + 1);

	for (tmp = tbl->desc; tmp->name; tmp++) {
		if (!tmp->builtin) {
			ret = write_desc_data(field, SLEN, tmp, entry);
			if (ret < 0)
				return ret;

			// TODO fix that horrible stuff
			strcat(fields, field);
			if ((tmp+1)->name)
				strcat(fields, ", ");
		}
	}

	ret = ovsdb_insert(&srdb->conf, tbl->name, fields, uuid);

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
		      void (*cb)(struct srdb_entry *))
{
	struct srdb_table *tbl;

	tbl = srdb_table_by_name(srdb->tables, table);
	if (!tbl)
		return;

	tbl->read = cb;
}
