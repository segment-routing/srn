BINDIRS=sr-client sr-ctrl sr-dnsproxy sr-routed tfoproxy sr-dnsfwd
OVSDIR=tools/openvswitch-2.6.1
OVSTARGETS=include/odp-netlink.h lib/vswitch-idl.h ovsdb/ovsdb-tool ovsdb/ovsdb-client ovsdb/ovsdb-server
clean_BINDIRS=$(addprefix clean_,$(BINDIRS))
ovsdb_check=$(wildcard $(OVSDIR)/config.status)

.PHONY: lib $(BINDIRS)

all: ovsdb $(BINDIRS)

lib:
	$(MAKE) -C lib

ovsdb:
ifeq ($(strip $(ovsdb_check)),)
		cd $(OVSDIR) && ./configure && cd -
endif
	$(MAKE) -C $(OVSDIR) $(OVSTARGETS)
	ln -sf ../$(OVSDIR)/ovsdb tools/

$(BINDIRS): lib
	$(MAKE) -C $@

clean: $(clean_BINDIRS)
	$(MAKE) -C lib clean

$(clean_BINDIRS):
	$(MAKE) -C $(patsubst clean_%,%,$@) clean

distclean: clean
	$(MAKE) -C $(OVSDIR) distclean
	rm -f tools/ovsdb
