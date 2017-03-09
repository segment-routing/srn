
#ifndef __SRDNS_H
#define __SRDNS_H

#include <stdint.h>

#include <ares_dns.h>

#define C_IN 1
#define T_AAAA 28
#define T_SRH 65280
#define T_OPT 41

#define DNS_HEADER_LENGTH 12
#define DNS_FIXED_HEADER_QUERY 4
#define EDNSFIXEDSZ 11

#define T_OPT_OPCODE_APP_NAME 65001
#define T_OPT_OPCODE_BANDWIDTH 65002
#define T_OPT_OPCODE_LATENCY 65003
#define T_OPT_OPCODE_ACCESS_ROUTER_NAME 65004

int make_dns_request(const char *destination, const char *servername, char *dest_addr);
int make_srdns_request(const char *destination, const char *servername, char *application_name,
                       uint32_t bandwidth, uint32_t latency,
                       char *dest_addr, char *src_prefix, char *binding_segment);
int sr_socket(int type, int proto, const char *dest, short dest_port,
              const char *dns_servername, char *application_name,
              uint32_t bandwidth, uint32_t latency);

#endif
