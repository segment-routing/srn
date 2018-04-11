
QUAGGA_BIN_FOLDER=$(HOME)/sr-quagga-bin

.PHONY: all sr-quagga clean

all: sr-quagga

sr-quagga: sr-quagga/Makefile
	$(MAKE) -C $@
	$(MAKE) -C $@ install
	ln -fs $(QUAGGA_BIN_FOLDER)/sbin/zebra zebra
	ln -fs $(CURDIR)/zebra ../bin/zebra
	ln -fs $(QUAGGA_BIN_FOLDER)/sbin/ospf6d ospf6d
	ln -fs $(CURDIR)/ospf6d ../bin/ospf6d

sr-quagga/configure:
	cd sr-quagga && ./bootstrap.sh

sr-quagga/Makefile: export LDFLAGS=-L$(CURDIR)/../lib
sr-quagga/Makefile: export CFLAGS=-I$(CURDIR)/../lib
sr-quagga/Makefile: sr-quagga/configure
	echo "$$LDFLAGS"
	cd sr-quagga && ./configure --prefix=$(QUAGGA_BIN_FOLDER) --with-gnu-ld

clean:
	if [ -f sr-quagga/Makefile ]; then \
		$(MAKE) -C sr-quagga clean; \
		$(MAKE) -C sr-quagga distclean || true; \
	fi
	rm -f zebra ../bin/zebra
	rm -f ospf6d ../bin/ospf6d
	rm -rf $(QUAGGA_BIN_FOLDER)
