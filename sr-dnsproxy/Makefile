CC=gcc
CFLAGS += -Wall # Enable the 'all' set of warnings
CFLAGS += -Werror # Treat all warnings as error
CFLAGS += -Wshadow # Warn when shadowing variables
CFLAGS += -Wextra # Enable additional warnings
CFLAGS += -O2 # -D_FORTIFY_SOURCE=2 # Add canary code, i.e. detect buffer overflows
CFLAGS += -fstack-protector-all # Add canary code to detect stack smashing
CFLAGS += -I../lib/c-ares -I../lib
LDFLAGS += -L../lib/c-ares/lib -L../lib
LDFLAGS += -Wl,-Bstatic -lcares -Wl,-Bdynamic -lpthread -lsr -ljansson
EXEC=proxy
SRC= $(wildcard *.c)
OBJ= $(SRC:.c=.o)


all: $(EXEC)

proxy: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

proxy.o: proxy.h

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: clean mrproper

clean:
	rm -rf *.o

mrproper: clean
	rm -rf $(EXEC)
