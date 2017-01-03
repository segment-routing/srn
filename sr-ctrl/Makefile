CC=gcc
CFLAGS=-g -Wall -W -O0 -I../lib
LDFLAGS=-L../lib -lsr -pthread
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
