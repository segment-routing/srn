CC=gcc
CFLAGS=-g -Wall -W -O2 -I../lib
LDFLAGS=-L../lib -lsr -pthread
SRC=sr-ctrl.c rules.c
OBJ=$(SRC:.c=.o)
EXEC=sr-ctrl

all:
	make $(EXEC)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(EXEC): $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS)

clean:
	rm -f $(EXEC) $(OBJ)
