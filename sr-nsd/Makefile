
.PHONY: all sr-quagga clean

all: sr-quagga

sr-quagga: sr-quagga/Makefile
	$(MAKE) -C $@
	$(MAKE) -C $@ install
	# To prevent name conflicts with the regular version of Quagga
	if ! [ -f srnzebra ]; then \
		ln -s sr-quagga-bin/sbin/zebra srnzebra; \
		chmod +x sr-quagga-bin/sbin/zebra srnzebra; \
	fi
	if ! [ -f srnospf6d ]; then \
		ln -s sr-quagga-bin/sbin/ospf6d srnospf6d; \
		chmod +x sr-quagga-bin/sbin/ospf6d srnospf6d; \
	fi

sr-quagga/configure:
	cd sr-quagga && ./bootstrap.sh

sr-quagga/Makefile: sr-quagga/configure
	cd sr-quagga && ./configure --prefix=$$(pwd)/../sr-quagga-bin

clean:
	$(MAKE) -C sr-quagga clean
	rm -f srnzebra
	rm -f srnospf6d
	rm -rf sr-quagga-bin
