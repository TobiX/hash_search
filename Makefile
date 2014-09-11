
CC := gcc
CFLAGS := -Wall -W -pedantic -std=gnu99 -Werror=implicit -O2
LIBS := -lcrypto

all: hash_search

hash_search: hash_search.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

clean:
	-rm hash_search *.o
