CC=gcc
CFLAGS=-Wall -W -O2 -I../lib -Werror -DHAVE_LIBMNL
LDFLAGS=-L../lib -lsr -pthread -ljansson -lmnl -lzlog
SRC=$(wildcard *.c)
OBJ=$(SRC:.c=.o)
EXEC=sr-routed

all:
	$(MAKE) $(EXEC)
	ln -fs $(CURDIR)/$(EXEC) ../bin/$(EXEC)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(EXEC): $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS)

clean:
	rm -f $(EXEC) $(OBJ) ../bin/$(EXEC)
