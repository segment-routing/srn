CC=gcc
CFLAGS=-Wall -W -O2 -I../lib -Wall -Werror
LDFLAGS=-static -L../lib -lsr -pthread -ljansson -lzlog
SRC=graph.c rules.c sr-ctrl.c
OBJ=$(SRC:.c=.o)
EXEC=sr-ctrl

all:
	$(MAKE) $(EXEC)
	ln -fs $(CURDIR)/$(EXEC) ../bin/$(EXEC)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(EXEC): $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS)

clean:
	rm -f $(EXEC) $(OBJ) ../bin/$(EXEC)
