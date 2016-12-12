#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "arraylist.h"
#include "rules.h"
#include "misc.h"

#define NEXT_ARG()								\
do {										\
	if (--vargc == 0) {							\
		pr_err("unexpected end of arguments after `%s'", *vargs); 	\
		goto out_err;							\
	}									\
	vargs++;								\
} while (0)

static int parse_path(struct rule *rule, char *buf)
{
	char **vargs, **orig_vargs;
	struct arraylist *path;
	int vargc, i;

	path = alist_new(sizeof(char *));
	if (!path)
		return -1;

	vargs = strsplit(buf, &vargc, ',');
	if (!vargs) {
		alist_destroy(path);
		return -1;
	}
	orig_vargs = vargs;

	for (i = 0; i < vargc; i++) {
		char *s;

		s = strdup(vargs[i]);
		alist_insert(path, &s);
	}

	free(orig_vargs);
	rule->path = path;

	return 0;
}

static struct rule *parse_rule(const char *line)
{
	char **vargs, **orig_vargs;
	struct rule *rule;
	char *buf;
	int vargc;

	rule = calloc(1, sizeof(*rule));
	if (!rule)
		return NULL;

	buf = strdup(line);
	if (!buf) {
		free(rule);
		return NULL;
	}

	vargs = strsplit(buf, &vargc, ' ');
	if (!vargs) {
		free(buf);
		free(rule);
		return NULL;
	}
	orig_vargs = vargs;

	do {
		if (!strcmp(*vargs, "default")) {
			rule->is_default = true;
		} else if (!strcmp(*vargs, "allow")) {
			rule->type = RULE_ALLOW;
		} else if (!strcmp(*vargs, "deny")) {
			rule->type = RULE_DENY;
		} else if (!strcmp(*vargs, "from")) {
			NEXT_ARG();
			strncpy(rule->from, *vargs, SLEN);
		} else if (!strcmp(*vargs, "to")) {
			NEXT_ARG();
			strncpy(rule->to, *vargs, SLEN);
		} else if (!strcmp(*vargs, "via")) {
			NEXT_ARG();
			if (parse_path(rule, *vargs) < 0) {
				pr_err("failed to parse path.");
				goto out_err;
			}
		} else if (!strcmp(*vargs, "last")) {
			NEXT_ARG();
			strncpy(rule->last, *vargs, SLEN);
		} else if (!strcmp(*vargs, "bw")) {
			NEXT_ARG();
			rule->bw = strtol(*vargs, NULL, 10);
		} else if (!strcmp(*vargs, "delay")) {
			NEXT_ARG();
			rule->delay = strtol(*vargs, NULL, 10);
		} else if (!strcmp(*vargs, "ttl")) {
			NEXT_ARG();
			rule->ttl = strtol(*vargs, NULL, 10);
		} else if (!strcmp(*vargs, "idle")) {
			NEXT_ARG();
			rule->idle = strtol(*vargs, NULL, 10);
		} else {
			pr_err("unknown argument `%s'.", *vargs);
			goto out_err;
		}
	} while (++vargs, --vargc > 0);

	if (rule->type == RULE_NONE) {
		pr_err("missing `allow' or `deny' keyword.");
		goto out_err;
	}

	if (rule->is_default && (*rule->from || *rule->to)) {
		pr_err("cannot use `from' or `to' keywords in default rule.");
		goto out_err;
	}

	if (!rule->is_default && !*rule->from && !*rule->to) {
		pr_err("missing `from' or `to' keywords in non-default rule.");
		goto out_err;
	}

	free(orig_vargs);
	free(buf);
	return rule;

out_err:
	free(orig_vargs);
	free(buf);
	free(rule);
	return NULL;
}

struct arraylist *load_rules(const char *fname, struct rule **defrule)
{
	struct arraylist *rules;
	struct rule *rule;
	char line[1024];
	int ln = 0;
	FILE *fp;

	*defrule = NULL;

	fp = fopen(fname, "r");
	if (!fp)
		return NULL;

	rules = alist_new(sizeof(struct rule *));

	while (fgets(line, 1024, fp)) {
		ln++;
		strip_crlf(line);
		if (*line == '#' || !*line)
			continue;

		rule = parse_rule(line);
		if (!rule) {
			pr_err("failed to parse rule at %s line %d.", fname, ln);
			goto out_err;
		}

		if (rule->is_default) {
			if (!*defrule) {
				*defrule = rule;
			} else {
				pr_err("duplicate default rule at %s line %d.", fname, ln);
				goto out_err;
			}

			continue;
		}

		if (alist_insert(rules, &rule) < 0) {
			pr_err("failed to insert rule at %s line %d.", fname, ln);
			goto out_err;
		}
	}

	fclose(fp);

	if (!*defrule) {
		rule = calloc(1, sizeof(*rule));
		rule->is_default = true;
		rule->type = RULE_DENY;
		*defrule = rule;
	}

	return rules;

out_err:
	alist_destroy(rules);
	fclose(fp);
	return NULL;
}

static bool match_rule(struct rule *rule, const char *from, const char *to)
{
	if (!strcmp(rule->from, from) && !strcmp(rule->to, to))
		return true;

	return false;
}

struct rule *match_rules(struct arraylist *rules, const char *from, const char *to)
{
	struct rule *match = NULL;
	struct rule *r;
	int i;

	for (i = 0; i < rules->elem_count; i++) {
		alist_get(rules, i, &r);
		if (match_rule(r, from, to))
			match = r;
	}

	return match;
}
