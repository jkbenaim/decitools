#include <endian.h>
#include <err.h>
#include <inttypes.h>
#include <iso646.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <unistd.h>

#include "deci.h"

extern char *__progname;
static void noreturn usage(void);

int main(int argc, char *argv[])
{
	int rc;
	char *machine = NULL;

	if (32 != sizeof(struct decihdr))
		errx(1, "decihdr size not 32");
	
	while ((rc = getopt(argc, argv, "m:")) != -1)
		switch (rc) {
		case 'm':
			if (machine)
				usage();
			machine = optarg;
			break;
		default:
			usage();
		}
	argc -= optind;
	argv += optind;
	if (*argv != NULL)
		usage();

	sdisp();

	return EXIT_SUCCESS;
}

static void noreturn usage(void)
{
	(void)fprintf(stderr, "usage: %s -m machine\n",
		__progname
	);
	exit(EXIT_FAILURE);
}
