
#ifndef __SRDNS_H
#define __SRDNS_H

#define T_OPT_OPCODE_APP_NAME 65001
#define T_OPT_OPCODE_BANDWIDTH 65002
#define T_OPT_OPCODE_LATENCY 65003

int make_srdns_request(const char *destination, const char *servername, char *application_name,
                       uint32_t bandwidth, uint32_t latency,
                       char *dest_addr, char *src_prefix, char *binding_segment);
int sr_socket(int type, int proto, const char *dest, short dest_port,
              const char *dns_servername, char *application_name,
              uint32_t bandwidth, uint32_t latency);

#endif
