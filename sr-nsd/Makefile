
.PHONY: all sr-quagga clean

all: sr-quagga

sr-quagga:
	cd $@ && ./bootstrap.sh && ./configure --prefix=$$(pwd)/../$@-bin
	$(MAKE) -C $@
	$(MAKE) -C $@ install
	# To prevent name conflicts with the regular version of Quagga
	ln -s $@-bin/sbin/zebra srnzebra
	ln -s $@-bin/sbin/ospf6d srnospf6d

clean:
	$(MAKE) -C sr-quagga clean
