/* hash_search.c: partially reverse MD5 or other hashes by finding bytes to add
 * to an existing file so that its MD5 hash begin with a specified prefix
 *
 * Copyright (C) 2003, Seth Schoen
 * Copyright (C) 2008, 2015, 2020 Tobias Gruetzmacher
 *
 * Permission is granted to any person obtaining a copy of this program
 * to deal in the program without restriction.
 *
 * Thanks to Zack Brown for suggesting the proper strategy for searching
 * (copying the md5 context data for re-use); thanks to Jef Pearlman for
 * suggesting linking against OpenSSL.
 *
 * Thanks to Aaron Swartz for testing on ppc.  Seemingly endian-safe. */

#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#ifdef _OPENMP
#include <omp.h>
#endif

/* block size for file reads */
#define SIZE 16384
/* maximum length of a formatted unsigned long long + \0 */
#define LONGLONGSTR 21

void usage(int ret)
{
	fputs("usage: hash_search [-b <bits>] [-d <digest>] [-l] hexdigits\n"
			"\t-b <bits>    number of bits to search (default: 24)\n"
			"\t-l           just list all possible matches, don't output modified file\n"
			"\t-d <digest>  use another digest instead of MD5\n", stderr);
	exit(ret);
}

void print_result(FILE *f, unsigned char *result, int len){
	int i;

	for (i = 0; i < len; i++) fprintf(f, "%02x", result[i]);
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

int get_value(char *str, unsigned char *s){
	unsigned int n = 0;
	unsigned int blah; /* %x conversion requires int */

	while ( n < strlen(str) ) {
		sscanf(str + n, "%2x", &blah);
		s[n/2] = (char) blah ;
		n += 2;
	};

	/* single hex digit if total hex digits is odd */
	if (strlen(str) % 2){
		s[(n-2)/2] <<= 4;
	}

	return 4 * strlen(str);

}

int main(int argc, char *argv[]){

	unsigned char *s;
	unsigned long long new_bytes;
	int L, bits, ch, shift, count = 0;
	unsigned long long max_search = 1 << 24;
	char buf[SIZE], make_matching = 1;
	unsigned char result[EVP_MAX_MD_SIZE];
	unsigned int result_len;
	EVP_MD_CTX *hash_state, *dup_hash_state;
	const EVP_MD *md = EVP_md5();
	ssize_t n;

	OpenSSL_add_all_digests();

	while ((ch = getopt(argc, argv, "b:d:l")) != -1) {
		switch (ch) {
			case 'b':
				shift = atol(optarg);
				if (shift >= 1 && shift <= 63)
					max_search = ((unsigned long long)1 << shift) - 1;
				else if (shift == 64)
					max_search = (unsigned long long)-1;
				else {
					fprintf(stderr, "invalid number of bits: %s\n", optarg);
					usage(1);
				}
				break;
			case 'd':
				md = EVP_get_digestbyname(optarg);

				if (!md) {
					printf("Unknown message digest %s\n", optarg);
					usage(1);
				}
				break;
			case 'l':
				make_matching = 0;
				break;
				/* case '?': - unknown options */
			default:
				usage(1);
		}
	}

	if (argc - optind != 1) usage(1);

	L = strlen(argv[optind]);

	/* find out what we're searching for */
	s = (unsigned char *)malloc((L+1)/2+1);
	bits = get_value(argv[optind], s);

	/* allocate memory for hash state */
	hash_state = EVP_MD_CTX_new();

	/* initialize hash */
	EVP_DigestInit_ex(hash_state, md, NULL);

	/* hash the existing file */
	fprintf(stderr, "reading file to hash from stdin...");
	if (isatty(0)){
		fprintf(stderr, "\n");
		while ((n = read(0, buf, SIZE))) {
			EVP_DigestUpdate(hash_state, buf, n);
			if (make_matching) reliable_write(1, buf, n);
		}
	} else {
		while ((n = read(0, buf, SIZE))) {
			EVP_DigestUpdate(hash_state, buf, n);
			if (make_matching) reliable_write(1, buf, n);
			/* progress indicator */
			if (!((count++)%256)) fprintf(stderr, ".");
		}
		fprintf(stderr, "\n");
	}

	/* announce the start of the search */
	fprintf(stderr, "beginning search (original hash = ");
	dup_hash_state = EVP_MD_CTX_new();
	EVP_MD_CTX_copy_ex(dup_hash_state, hash_state);
	EVP_DigestFinal_ex(dup_hash_state, result, &result_len);
	EVP_MD_CTX_free(dup_hash_state);
	print_result(stderr, result, result_len);
	fprintf(stderr, ")\nsearching 0 to %#llx...\n", max_search);

	/* do the search */
	#pragma omp parallel
	{
#ifdef _OPENMP
		if (omp_get_thread_num() == 0)
			fprintf(stderr, "Using %i threads for search.\n", omp_get_num_threads());
#endif

		EVP_MD_CTX *final_state = EVP_MD_CTX_new();

		char * data = malloc(LONGLONGSTR);
		size_t datalen;

		#pragma omp for schedule(static) private(result,result_len)
		for (new_bytes = 0; new_bytes < max_search; new_bytes++){
			EVP_MD_CTX_copy_ex(final_state, hash_state);

			datalen = snprintf(data, LONGLONGSTR, "%lli", new_bytes);
			EVP_DigestUpdate(final_state, data, datalen);
			EVP_DigestFinal_ex(final_state, result, &result_len);
			if (!memcmp(result, s, bits/8)) {
				/* just one last nibble? */
				if ((bits%8 == 0) || ((result[bits/8] & 0xf0) == (s[bits/8] & 0xf0))){
					#pragma omp critical
					if (make_matching) {
						/* goal is to output an actual matching file */
						fprintf(stderr, "found match!\n");
						fprintf(stderr, "new hash is ");
						print_result(stderr, result, result_len);
						fprintf(stderr, "\n");
						reliable_write(1, data, datalen);
						close(1);
						exit(0);
					} else {
						/* goal is to display all possible matches */
						print_result(stdout, result, result_len);
						fprintf(stdout, " ascii %lli\n", new_bytes);
					}
				}
			}
		}

		EVP_MD_CTX_free(final_state);
		free(data);
	}

	/* free memory */
	EVP_MD_CTX_free(hash_state);
	free(s);

	if (make_matching) fprintf(stderr, "no match found.\n");
	/* if the goal was to output a matching file, then fail if we got
	 * here (because we would have exited above if we had succeeded */
	return make_matching;
}
