
QUAGGA_BIN_FOLDER=$(HOME)/sr-quagga-bin/
SR_LIB=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))/../lib

.PHONY: all sr-quagga clean

all: sr-quagga

sr-quagga: sr-quagga/Makefile
	$(MAKE) -C $@
	$(MAKE) -C $@ install
	if ! [ -f zebra ]; then \
		ln -s $(QUAGGA_BIN_FOLDER)/sbin/zebra zebra; \
		chmod +x $(QUAGGA_BIN_FOLDER)/sbin/zebra zebra; \
	fi
	if ! [ -f ospf6d ]; then \
		ln -s $(QUAGGA_BIN_FOLDER)/sbin/ospf6d ospf6d; \
		chmod +x $(QUAGGA_BIN_FOLDER)/sbin/ospf6d ospf6d; \
	fi

sr-quagga/configure:
	cd sr-quagga && ./bootstrap.sh

sr-quagga/Makefile: sr-quagga/configure
	cd sr-quagga && env CPPFLAGS="-I$(SR_LIB)" LDFLAGS="-L$(SR_LIB)" ./configure --prefix=$(QUAGGA_BIN_FOLDER)

clean:
	$(MAKE) -C sr-quagga clean
	rm -f zebra
	rm -f ospf6d
	rm -rf $(QUAGGA_BIN_FOLDER)
