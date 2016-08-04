#include <stdio.h>
#include <values.h> /* LONG_MAX */
#include <stdlib.h>  /* strtol */
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

int main(int argc, char* argv[])
{
	int ret = 1;
	char *str, *endptr;
	mode_t mode;

	if(argc < 3) {
		printf("usage %s mode filename\n", argv[0]);
		return ret;
	}

	str  = argv[1];
	mode = strtol(str, &endptr, 8);

	/* Check for various possible errors */

	if ((errno == ERANGE && (mode == LONG_MAX || mode == LONG_MIN))
			|| (errno != 0 && mode == 0)) {
		perror("strtol");
		exit(EXIT_FAILURE);
	}

	if (endptr == str) {
		fprintf(stderr, "No digits were found\n");
		exit(EXIT_FAILURE);
	}

	/* If we got here, strtol() successfully parsed a number */

	printf("chmod %o %s\n", mode, argv[2]);

	ret = chmod(argv[2], mode);

	if(ret != 0) {
		perror("chmod");
	}

	return ret;
}

