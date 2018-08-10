CC=gcc
AR=ar
CFLAGS=-g -Wall -W -O2 -Wall -Werror
CFLAGS += -I./c-ares
SRC=arraylist.c hashmap.c lpm.c misc.c srdb.c srdns.c linked_list.c sbuf.c llist.c
OBJ=arraylist.o hashmap.o lpm.o misc.o srdb.o linked_list.o sbuf.o llist.o
DNSOBJ=srdns.o

LIBFILE=libsr.a
DNSLIBFILE=libsrdns.a

all: $(LIBFILE) $(DNSLIBFILE)
#	cd libredblack-1.3 && ./configure --with-rbgen=no && make && cd .. && ln -s libredblack-1.3/.libs/libredblack.a

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIBFILE): $(OBJ)
	$(AR) r $@ $(OBJ)

$(DNSLIBFILE): ares $(DNSOBJ)
	$(AR) r $@ $(DNSOBJ)

ares:
	cd c-ares && cmake -DCARES_STATIC=1 -DCARES_SHARED=0 && $(MAKE) && cd ..

clean:
	rm -f $(LIBFILE) $(OBJ) $(DNSOBJ) libredblack.a
	cd c-ares && make clean && cd ..
#	cd libredblack-1.3 && make clean && cd .. && rm -f libredblack.a
