CC=gcc
CFLAGS=-g -Wall -W -O2 -I../lib -I../lib/c-ares -Werror
LDFLAGS=-L../lib -L../lib/c-ares/lib -lsr -Wl,-Bstatic -lcares -Wl,-Bdynamic -pthread
SRC=sr-testdns.c
OBJ=$(SRC:.c=.o)
EXEC=sr-testdns

all:
	$(MAKE) $(EXEC)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(EXEC): $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS)

clean:
	rm -f $(EXEC) $(OBJ)
