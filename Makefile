
OPENMP := yes
CC := gcc
CFLAGS := -g -Wall -W -pedantic -std=gnu99 -Werror=implicit -O2
LIBS := -lcrypto

ifeq ($(OPENMP),yes)
	CFLAGS += -fopenmp
	LDFLAGS += -fopenmp
endif

all: hash_search

hash_search: hash_search.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

clean:
	-rm hash_search *.o

check: hash_search
	! ./hash_search -b 8 dead < /dev/null 2>/dev/null
	test `./hash_search -b 32 dead < /dev/null 2>/dev/null |md5sum| cut -c 1-4` = dead
