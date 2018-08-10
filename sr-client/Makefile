CC=gcc
CFLAGS += -std=c99 # Define which version of the C standard to use
CFLAGS += -Wall # Enable the 'all' set of warnings
CFLAGS += -Werror # Treat all warnings as error
CFLAGS += -Wshadow # Warn when shadowing variables
CFLAGS += -Wextra # Enable additional warnings
CFLAGS += -O2 # -D_FORTIFY_SOURCE=2 # Add canary code, i.e. detect buffer overflows
#CFLAGS += -fstack-protector-all # Add canary code to detect stack smashing
CFLAGS += -D_POSIX_C_SOURCE=201112L -D_XOPEN_SOURCE # feature_test_macros for getpot and getaddrinfo
CFLAGS += -I../lib/c-ares -I../lib
LDFLAGS += -L../lib -L../lib/c-ares/lib
LDFLAGS += -lsrdns -Wl,-Bstatic -lcares -Wl,-Bdynamic -lpthread
EXEC=client
SRC= $(wildcard *.c)
OBJ= $(SRC:.c=.o)


all: $(EXEC)
	ln -fs $(CURDIR)/$(EXEC) ../bin/$(EXEC)

client: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: clean mrproper

clean:
	rm -rf *.o
	rm -rf $(EXEC) $(OBJ) ../bin/$(EXEC)
