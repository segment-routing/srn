#ifndef _RULES_H
#define _RULES_H

#include <srdb.h>

enum ruletype {
	RULE_NONE,
	RULE_ALLOW,
	RULE_DENY,
};

enum matchtype {
	MATCH_NONE,
	MATCH_NAME,
	MATCH_REGEX,
	MATCH_PREFIX,
};

struct rule {
	bool is_default;
	enum ruletype type;
	char from[SLEN + 1];
	char to[SLEN + 1];
	struct arraylist *path;
	char last[SLEN + 1];
	int bw;
	int delay;
	int ttl;
	int idle;
};

struct arraylist *load_rules(const char *fname, struct rule **defrule);
void destroy_rules(struct arraylist *rules, struct rule *defrule);
struct rule *match_rules(struct arraylist *rules, const char *from, const char *to);

#endif
