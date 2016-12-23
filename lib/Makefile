CC=gcc
AR=ar
CFLAGS=-g -Wall -W -O0
CFLAGS += -I../cares/include
LDFLAGS += -L../cares/lib
LDFLAGS += -lcares
SRC=arraylist.c hashmap.c lpm.c misc.c srdb.c srdns.c
OBJ=$(SRC:.c=.o)
LIBFILE=libsr.a

all: $(LIBFILE)
#	cd libredblack-1.3 && ./configure --with-rbgen=no && make && cd .. && ln -s libredblack-1.3/.libs/libredblack.a

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIBFILE): $(OBJ)
	$(AR) r $@ $(OBJ)

clean:
	rm -f $(LIBFILE) $(OBJ) libredblack.a
#	cd libredblack-1.3 && make clean && cd .. && rm -f libredblack.a
