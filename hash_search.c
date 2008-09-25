/* hash_search.c: partially reverse MD5 hashes by finding bytes to add
 * to an existing file so that its MD5 hash begin with a specified prefix
 *
 * link with -lcrypto   (use libcrypto, supplied by OpenSSL)
 * 
 * Copyright (C) 2003, Seth Schoen
 *
 * Permission is granted to any person obtaining a copy of this program
 * to deal in the program without restriction.
 *
 * Thanks to Zack Brown for suggesting the proper strategy for searching
 * (copying the md5 context data for re-use); thanks to Jef Pearlman for
 * suggesting linking against OpenSSL.
 *
 * Thanks to Aaron Swartz for testing on ppc.  Seemingly endian-safe. */

#include <openssl/md5.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

/* block size for file reads */
#define SIZE 16384

#define SAVE_STATE memcpy(dup_md5_state, md5_state, sizeof(MD5_CTX))
#define RESTORE_STATE memcpy(md5_state, dup_md5_state, sizeof(MD5_CTX))

/* This should be a command-line option.  If make_matching is 1, the
 * program outputs a matching file on stdout.  If make_matching is 0,
 * the program instead outputs a list of potential matches (mainly useful
 * for speed testing or debugging). */
#define make_matching 1

void print_result(FILE *f, unsigned char *result){
	int i;

	for (i = 0; i < 16; i++) fprintf(f, "%02x", result[i]);
}

size_t reliable_write(int fd, void *buf, size_t count){
	size_t orig = count;
	size_t temp;

	while (count) {
		temp = write(fd, buf, count);
		if (count - temp){
			buf = (char*)buf + temp;
		}
		count -= temp;
	}

	return orig;
}

int get_value(char *argv[], unsigned char *s){
	unsigned int n = 0;
	unsigned int blah; /* %x conversion requires int */

	while ( n < strlen(argv[1]) ) {
		sscanf(argv[1] + n, "%2x", &blah);
		s[n/2] = (char) blah ;
		n += 2;
	};

	/* single hex digit if total hex digits is odd */
	if (strlen(argv[1]) % 2){
		s[(n-2)/2] <<= 4;
	}

	return 4 * strlen(argv[1]);

}

int main(int argc, char *argv[]){

	unsigned char *s;
	unsigned long long *new_byte;
	int L, bits, count = 0;
	unsigned long long max_search;
	char buf[SIZE];
	unsigned char result[16];
	MD5_CTX *md5_state, *dup_md5_state;
	ssize_t n;

	if (argc < 2){
		fprintf(stderr, "usage: %s hexdigits [bits]\n", argv[0]);
		exit(1);
	}

	L = strlen(argv[1]);

	/* find out what we're searching for */
	s = (unsigned char *)malloc((L+1)/2+1);
	bits = get_value(argv, s);

	/* and see how long to search */
	if (argc > 2) {
		unsigned int shift = atol(argv[2]);
		if (shift >= 1 && shift <= 63)
			max_search = ((unsigned long long)1 << shift) - 1;
		else if (shift == 64)
			max_search = (unsigned long long)-1;
		else {
			fprintf(stderr, "invalid number of bits: %s\n", argv[2]);
			exit(1);
		}

	} else {
		max_search = 256*256*256;
	}

	/* allocate memory for hash state */
	md5_state = (MD5_CTX *)malloc(sizeof(MD5_CTX));
	dup_md5_state = (MD5_CTX *)malloc(sizeof(MD5_CTX));
	new_byte = (unsigned long long *)malloc(sizeof(unsigned long long *));

	/* initialize hash */
	MD5_Init(md5_state);

	/* hash the existing file */
	fprintf(stderr, "reading file to hash from stdin...");
	if (isatty(0)){
		fprintf(stderr, "\n");
		while ((n = read(0, buf, SIZE))) {
			MD5_Update(md5_state, buf, n);
			if (make_matching) reliable_write(1, buf, n);
		}
	} else {
		while ((n = read(0, buf, SIZE))) {
			MD5_Update(md5_state, buf, n);
			if (make_matching) reliable_write(1, buf, n);
			/* progress indicator */
			if (!((count++)%256)) fprintf(stderr, ".");
		}
		fprintf(stderr, "\n");
	}

	/* announce the start of the search */
	fprintf(stderr, "beginning search (original hash = ");
	SAVE_STATE;
	MD5_Final(result, md5_state);
	print_result(stderr, result);
	RESTORE_STATE;
	fprintf(stderr, ")\nsearching 0 to %#llx ... ", max_search);

	/* do the search */
	for (*new_byte = 0; *new_byte < max_search; (*new_byte)++){
		SAVE_STATE;

		MD5_Update(md5_state, (char *)new_byte, sizeof(int));
		MD5_Final(result, md5_state);
		if (!memcmp(result, s, bits/8)) {
			/* just one last nibble? */
			if ((bits%8 == 0) || ((result[bits/8] & 0xf0) == (s[bits/8] & 0xf0))){
			if (make_matching) {
				/* goal is to output an actual matching file */
				fprintf(stderr, "found match!\n");
				fprintf(stderr, "new hash is ");
				print_result(stderr, result);
				fprintf(stderr, "\n");
				reliable_write(1, new_byte, 4);
				close(1);
				exit(0);
			} else {
				/* goal is to display all possible matches */
				print_result(stdout, result);
				fprintf(stdout, " bytes %#llx\n", *new_byte);
			}
			}
		}

		RESTORE_STATE;
	}

	/* free memory */
	free(md5_state); free(dup_md5_state); free(s);

	if (make_matching) fprintf(stderr, "no match found.\n");
	/* if the goal was to output a matching file, then fail if we got
	 * here (because we would have exited above if we had succeeded */
	return make_matching;
}
