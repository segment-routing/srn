#ifndef __ADD_ROUTE_H__
#define __ADD_ROUTE_H__

int add_route(struct rtnl_handle *rth, const char *dst, const char *dev,
	      __u32 tid, const char *segs);
int change_route(struct rtnl_handle *rth, const char *dst_str, const char *dev,
		 __u32 tid, const char *segs);

#endif

