
CC := gcc
CFLAGS := -Wall -W -pedantic -std=gnu99 -Werror=implicit -O2
LDFLAGS := -lcrypto

all: hash_search

hash_search: hash_search.o

clean:
	-rm hash_search *.o
