#include <asm/types.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <linux/lwtunnel.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/seg6.h>
#include <linux/seg6_hmac.h>
#include <linux/seg6_iptunnel.h>
#include <linux/seg6_local.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "libnetlink.h"


// Need special prefix on the loopback ! Or add a rule such that such prefix is
// redirected to the normal table

static struct ipv6_sr_hdr *parse_srh(const char *segs, int hmac, bool encap)
{
	struct ipv6_sr_hdr *srh;
	int nsegs = 0;
	int srhlen;
	char *segbuf;
	char *s;
	int i;

	segbuf = strdup(segs);
	s = segbuf;
	for (i = 0; *s; *s++ == ',' ? i++ : *s);
	nsegs = i + 1;

	if (!encap)
		nsegs++;

	srhlen = 8 + 16*nsegs;

	if (hmac)
		srhlen += 40;

	srh = malloc(srhlen);
	memset(srh, 0, srhlen);

	srh->hdrlen = (srhlen >> 3) - 1;
	srh->type = 4;
	srh->segments_left = nsegs - 1;
	srh->first_segment = nsegs - 1;

	if (hmac)
		srh->flags |= SR6_FLAG1_HMAC;

	i = srh->first_segment;
	for (s = strtok(segbuf, ","); s; s = strtok(NULL, ",")) {
		struct in6_addr addr;
		inet_pton(AF_INET6, s, &addr);
		memcpy(&srh->segments[i], &addr, sizeof(struct in6_addr));
		i--;
	}

	if (hmac) {
		struct sr6_tlv_hmac *tlv;

		tlv = (struct sr6_tlv_hmac *)((char *)srh + srhlen - 40);
		tlv->tlvhdr.type = SR6_TLV_HMAC;
		tlv->tlvhdr.len = 38;
		tlv->hmackeyid = htonl(hmac);
	}

	free(segbuf);

	return srh;
}

static int encap_seg6local(struct rtattr *rta, size_t len, const char *segs)
{
	// action End.B6.Encaps
	rta_addattr32(rta, len, SEG6_LOCAL_ACTION,
		      SEG6_LOCAL_ACTION_END_B6_ENCAP);

	// srh segs <segments>
	struct ipv6_sr_hdr *srh = parse_srh(segs, 0, 1);
	int srhlen = (srh->hdrlen + 1) << 3;
	rta_addattr_l(rta, len, SEG6_LOCAL_SRH, srh, srhlen);
	free(srh);

	return 0;
}

static int lwt_encap(struct rtattr *rta, size_t len, const char *segs)
{
	// seg6local
	__u16 type = LWTUNNEL_ENCAP_SEG6_LOCAL;
	struct rtattr *nest = rta_nest(rta, 1024, RTA_ENCAP);

	// action End.B6.Encaps srh segs <segments>
	if (encap_seg6local(rta, len, segs))
		return -1;
	
	rta_nest_end(rta, nest);
	rta_addattr16(rta, 1024, RTA_ENCAP_TYPE, type);
	return 0;
}

/**
 * Same as executing
 * ip -6 route add <dst_str> encap seg6local action End.B6.Encaps srh segs <segs> dev <dev> table <tid>
 */
int modify_route(struct rtnl_handle *rth, const char *dst_str, const char *dev,
		 __u32 tid, const char *segs, bool new)
{
	// ip -6 route
	struct {
		struct nlmsghdr	n;
		struct rtmsg	r;
		char		buf[1024];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
		.n.nlmsg_flags = NLM_F_REQUEST,
		.n.nlmsg_type = RTM_NEWROUTE,
		.r.rtm_family = AF_INET6,
		.r.rtm_table = RT_TABLE_MAIN,
		.r.rtm_scope = RT_SCOPE_UNIVERSE,
		.r.rtm_protocol = RTPROT_BOOT,
		.r.rtm_type = RTN_UNICAST
	};

	// add or change
	if (new)
		req.n.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
	else
		req.n.nlmsg_flags |= NLM_F_REPLACE;

	// <segment>
	struct in6_addr dst;
	if (!inet_pton(AF_INET6, dst_str, &dst)) {
		perror("Cannot parse segment as an IPv6 address");
		return -1;
	}
	req.r.rtm_dst_len = sizeof(dst) * 8;
	addattr_l(&req.n, sizeof(req), RTA_DST, &dst, sizeof(dst));

	// dev <device>
	int idx = if_nametoindex(dev);
	if (!idx) {
		perror("Cannot find device eth0");
		return -1;
	}
	addattr32(&req.n, sizeof(req), RTA_OIF, idx);

	// table localsid
	if (tid < 256) {
		req.r.rtm_table = tid;
	} else {
		req.r.rtm_table = RT_TABLE_UNSPEC;
		addattr32(&req.n, sizeof(req), RTA_TABLE, tid);
	}

	// encap seg6local action End.B6.Encaps srh segs <segments>

	char buf[1024];
	struct rtattr *rta = (void *)buf;

	rta->rta_type = RTA_ENCAP;
	rta->rta_len = RTA_LENGTH(0);

	if (lwt_encap(rta, sizeof(buf), segs)) {
		return -1;
	}

	if (rta->rta_len > RTA_LENGTH(0))
		addraw_l(&req.n, 1024, RTA_DATA(rta), RTA_PAYLOAD(rta));

	// send request and listen for answer
	if (rtnl_talk(rth, &req.n, NULL) < 0) {
		perror("The netlink request failed");
		return -1;
	}

	return 0;
}

/**
 * Same as executing
 * ip -6 route add <dst_str> encap seg6local action End.B6.Encaps srh segs <segs> dev <dev> table <tid>
 */
int add_route(struct rtnl_handle *rth, const char *dst_str, const char *dev,
	      __u32 tid, const char *segs)
{
	return modify_route(rth, dst_str, dev, tid, segs, true);
}

/**
 * Same as executing
 * ip -6 route change <dst_str> encap seg6local action End.B6.Encaps srh segs <segs> dev <dev> table <tid>
 */
int change_route(struct rtnl_handle *rth, const char *dst_str, const char *dev,
		 __u32 tid, const char *segs)
{
	return modify_route(rth, dst_str, dev, tid, segs, false);
}

