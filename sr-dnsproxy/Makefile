CC=gcc
CFLAGS += -Wall # Enable the 'all' set of warnings
CFLAGS += -Werror # Treat all warnings as error
CFLAGS += -Wshadow # Warn when shadowing variables
CFLAGS += -Wextra # Enable additional warnings
CFLAGS += -O2 # -D_FORTIFY_SOURCE=2 # Add canary code, i.e. detect buffer overflows
#CFLAGS += -fstack-protector-all # Add canary code to detect stack smashing
CFLAGS += -I../lib/c-ares -I../lib
LDFLAGS += -static -L../lib/c-ares/lib -L../lib -pthread -lcares -lsr -lsrdns -ljansson -lzlog
EXEC=sr-dnsproxy
SRC= $(wildcard *.c)
OBJ= $(SRC:.c=.o)


all: $(EXEC)
	ln -fs $(CURDIR)/$(EXEC) ../bin/$(EXEC)

$(EXEC): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

proxy.o: proxy.h

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: clean mrproper

clean:
	rm -rf *.o
	rm -rf $(EXEC) $(OBJ) ../bin/$(EXEC)
