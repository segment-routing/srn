CC=gcc
CFLAGS += -std=c99 # Define which version of the C standard to use
CFLAGS += -Wall # Enable the 'all' set of warnings
#CFLAGS += -Werror # Treat all warnings as error
CFLAGS += -Wshadow # Warn when shadowing variables
CFLAGS += -Wextra # Enable additional warnings
CFLAGS += -O2 -D_FORTIFY_SOURCE=2 # Add canary code, i.e. detect buffer overflows
CFLAGS += -fstack-protector-all # Add canary code to detect stack smashing
CFLAGS += -D_POSIX_C_SOURCE=201112L -D_XOPEN_SOURCE # feature_test_macros for getpot and getaddrinfo
CFLAGS += -I/home/vagrant/cares/include -I/home/vagrant/lib
LDFLAGS += -L/home/vagrant/cares/lib -L/home/vagrant/lib
LDFLAGS += -lcares -lpthread -lsr
EXEC=proxy
SRC= $(wildcard *.c)
OBJ= $(SRC:.c=.o)


all: $(EXEC)

proxy: $(OBJ)
	@$(CC) -o $@ $^ $(LDFLAGS)

proxy.o: proxy.h

%.o: %.c
	@$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: clean mrproper

clean:
	@rm -rf *.o

mrproper: clean
	@rm -rf $(EXEC)
