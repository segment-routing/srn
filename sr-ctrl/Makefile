CC=gcc
CFLAGS=-Wall -W -O2 -I../lib -Wall -Werror
LDFLAGS=-L../lib -lsr -pthread -ljansson
SRC=graph.c rules.c sr-ctrl.c
OBJ=$(SRC:.c=.o)
EXEC=sr-ctrl

all:
	$(MAKE) $(EXEC)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(EXEC): $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS)

clean:
	rm -f $(EXEC) $(OBJ)
