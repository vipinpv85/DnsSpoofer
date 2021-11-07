#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h>
#include <arpa/inet.h>

uint16_t dnsPort = 53;

void usage (void)
{
	fprintf(stdout, "INFO: ----------- DNS SPOOFER -----------\n");
	fprintf(stdout, "INFO: ./ dnsSpoofer			- default DNS port 53\n");
	fprintf(stdout, "INFO: ./ dnsSpoofer [dns port]	- run with user defined dns port\n");
	fprintf(stdout, "INFO: ----------- ----------- -----------\n");
}

int main (int argc, char *argv[])
{
	fprintf(stdout, "DEBUG: args\n");
	for (int i = 0; i < argc; i++)
		fprintf(stdout, "DEBUG: argv[%d] - (%s)\n", i, argv[i]);

	/* check if DNS port is given */
	if (argc > 2) {
		fprintf(stderr, "ERR: unexpected user arguments!\n\n");
		usage();
		return -1;
	}

	/* check if dns port number is within bounds */
	if ((NULL == argv[1]) || (strlen(argv[1]) > 4) || (strlen(argv[1]) == 0)) {
		fprintf(stderr, "ERR: dns port arguemnt is incorrect!\n\n");
		return -2;
	}

	char *digit = argv[1];
	size_t len = strlen(argv[1]);

	for (int i = 0; i < len; i++, digit+= 1)
	{
		if (!isdigit(*digit)) {
			fprintf(stderr, "ERR: dns port arguemnt is not uint16_t digits!\n\n");
			return -3;
		}
	}

	dnsPort = atoi(argv[1]);
	fprintf(stdout, "DEBUG: DNS port %u\n", dnsPort);

	return 0;
}
