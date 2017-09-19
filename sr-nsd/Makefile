
QUAGGA_BIN_FOLDER=$(HOME)/sr-quagga-bin/

.PHONY: all sr-quagga clean

all: sr-quagga

sr-quagga: sr-quagga/Makefile
	$(MAKE) -C $@
	$(MAKE) -C $@ install
	# To prevent name conflicts with the regular version of Quagga
	if ! [ -f srnzebra ]; then \
		ln -s $(QUAGGA_BIN_FOLDER)/sbin/zebra srnzebra; \
		chmod +x $(QUAGGA_BIN_FOLDER)/sbin/zebra srnzebra; \
	fi
	if ! [ -f srnospf6d ]; then \
		ln -s $(QUAGGA_BIN_FOLDER)/sbin/ospf6d srnospf6d; \
		chmod +x $(QUAGGA_BIN_FOLDER)/sbin/ospf6d srnospf6d; \
	fi

sr-quagga/configure:
	cd sr-quagga && ./bootstrap.sh

sr-quagga/Makefile: sr-quagga/configure
	cd sr-quagga && ./configure --prefix=$(QUAGGA_BIN_FOLDER)

clean:
	$(MAKE) -C sr-quagga clean
	rm -f srnzebra
	rm -f srnospf6d
	rm -rf $(QUAGGA_BIN_FOLDER)
