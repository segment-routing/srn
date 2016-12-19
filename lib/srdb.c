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
	char line[BUFLEN];
	char cmd[BUFLEN];
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
			const char *fields)
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

static void fill_srdb_entry(struct srdb_descriptor *desc, char **vargs)
{
	int i, idx;

	for (i = 0; *vargs; vargs++, i++) {
		idx = find_desc_fromidx(desc, i);
		if (idx < 0)
			continue;

		switch (desc[idx].type) {
		case SRDB_STR:
			strncpy((char *)desc[idx].data, *vargs, desc[idx].maxlen);
			break;
		case SRDB_INT:
			*(int *)desc[idx].data = strtol(*vargs, NULL, 10);
			break;
		}
	}
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

	buf2 = calloc(1, n);
	if (!buf2)
		return NULL;

	for (n = 0, s = buf; *s; s++) {
		if (*s != '"')
			buf2[n++] = *s;
	}

	return buf2;
}

static struct srdb_descriptor flowreq_desc_tmpl[] = {
	{
		.name	= "row",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.builtin = true,
	},
	{
		.name	= "action",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.builtin = true,
	},
	{
		.name	= "_version",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.builtin = true,
	},
	{
		.name	= "destination",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
	},
	{
		.name	= "dstaddr",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
	},
	{
		.name	= "source",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
	},
	{
		.name	= "bandwidth",
		.type	= SRDB_INT,
		.maxlen	= sizeof(int),
	},
	{
		.name	= "delay",
		.type	= SRDB_INT,
		.maxlen	= sizeof(int),
	},
	{
		.name	= "router",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
	},
	{
		.name	= "status",
		.type	= SRDB_INT,
		.maxlen	= sizeof(int),
	},
	{
		.name	= NULL,
	},
};

static inline void fill_flowreq_desc(struct srdb_descriptor *desc,
				     struct srdb_entry *entry)
{
	struct srdb_flowreq_entry *req = (struct srdb_flowreq_entry *)entry;

	desc[0].data = req->_row;
	desc[1].data = req->_action;
	desc[2].data = req->_version;

	desc[3].data = req->destination;
	desc[4].data = req->dstaddr;
	desc[5].data = req->source;
	desc[6].data = &req->bandwidth;
	desc[7].data = &req->delay;
	desc[8].data = req->router;
	desc[9].data = &req->status;
}

static struct srdb_table srdb_tables[] = {
	{
		.name		= "FlowReq",
		.entry_size	= sizeof(struct srdb_flowreq_entry),
		.desc_tmpl	= flowreq_desc_tmpl,
		.desc_size	= sizeof(flowreq_desc_tmpl),
		.fill		= fill_flowreq_desc,
	},
	{
		.name		= NULL,
	},
};

struct srdb_table *srdb_get_tables(void)
{
	struct srdb_table *tbl;

	tbl = memdup(srdb_tables, sizeof(srdb_tables));
	if (!tbl)
		return NULL;

	tbl[0].desc = memdup(tbl[0].desc_tmpl, tbl[0].desc_size);
	if (!tbl[0].desc) {
		free(tbl);
		return NULL;
	}

	return tbl;
}

void srdb_free_tables(struct srdb_table *tbl)
{
	struct srdb_table *tmp = tbl;

	while (tmp->name) {
		free(tmp->desc);
		tmp++;
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
	struct srdb_descriptor *desc;
	struct srdb_table *tbl = arg;
	struct srdb_entry *entry;
	char **vargs;
	char *buf2;
	int vargc;

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

	memset(&entry, 0, sizeof(entry));

	if (!strcmp(*vargs, "row")) {
		fill_srdb_index(tbl->desc, vargs);
		free(vargs);
		free(buf2);
		return;
	}

	desc = memdup(tbl->desc, tbl->desc_size);
	if (!desc) {
		free(vargs);
		free(buf2);
		return;
	}

	entry = calloc(1, tbl->entry_size);
	if (!entry) {
		free(desc);
		free(vargs);
		free(buf2);
		return;
	}

	tbl->fill(desc, entry);
	fill_srdb_entry(desc, vargs);

	free(desc);
	free(vargs);
	free(buf2);

	tbl->read(entry);

	free(entry);
}

int srdb_monitor(struct srdb *srdb, struct srdb_table *tbl, const char *columns)
{
	int ret;

	ret = ovsdb_monitor(&srdb->conf, tbl->name, columns, srdb_read, tbl);

	return ret;
}

static int write_desc_data(char *buf, size_t size,
			   struct srdb_descriptor *desc)
{
	int wr = -1;

	switch (desc->type) {
	case SRDB_STR:
		wr = snprintf(buf, size, "\"%s\": \"%s\"", desc->name,
			      (char *)desc->data);
		break;
	case SRDB_INT:
		wr = snprintf(buf, size, "\"%s\": %d", desc->name,
			      *(int *)desc->data);
		break;
	}

	return wr;
}

int srdb_update(struct srdb *srdb, struct srdb_table *tbl,
		struct srdb_entry *entry, struct srdb_descriptor *desc)
{
	char field_update[SLEN + 1];
	int ret;

	write_desc_data(field_update, SLEN, desc);

	ret = ovsdb_update(&srdb->conf, tbl->name, entry->row, field_update);

	return ret;
}

int srdb_insert(struct srdb *srdb, struct srdb_table *tbl,
		struct srdb_entry *entry)
{
	struct srdb_descriptor *desc, *tmp;
	char fields[BUFLEN + 1];
	int ret, wr = 0;

	desc = memdup(tbl->desc, tbl->desc_size);
	if (!desc)
		return -1;

	tbl->fill(desc, entry);

	for (tmp = desc; tmp->name; tmp++) {
		if (tmp->data && !tmp->builtin) {
			ret = write_desc_data(fields, BUFLEN - wr, tmp);
			if (ret < 0) {
				free(desc);
				return ret;
			}
			wr += ret;
		}
	}

	free(desc);

	if (!wr)
		return 0;

	ret = ovsdb_insert(&srdb->conf, tbl->name, fields);

	return 0;
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
