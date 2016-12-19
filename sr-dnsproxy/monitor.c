
#include "proxy.h"

struct queue_thread replies_with_srh;

int ovsdb_process_event() {
  return 0;
}

void init_monitor() {
  // TODO Init ovsdb monitoring
  queue_init(&replies_with_srh, MAX_QUERIES);
}

void close_monitor() {
  // TODO Free ovsdb monitoring
  queue_destroy(&replies_with_srh);
}
