CC=gcc
CFLAGS=-g -Wall -W -O0 -I../lib -Werror
LDFLAGS=-L../lib -lsr -pthread -ljansson
SRC=sr-routed.c
OBJ=$(SRC:.c=.o)
EXEC=sr-routed

all:
	$(MAKE) $(EXEC)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(EXEC): $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS)

clean:
	rm -f $(EXEC) $(OBJ)
