#include "dnsSpoof.h"

#include <stdio.h>
#include <string.h>

uint16_t dnsPort = 53;

void usage (void)
{
	fprintf(stdout, "INFO: ----------- DNS SPOOFER -----------\n");
	fprintf(stdout, "INFO: ./ dnsSpoofer		- default DNS port 53\n");
	fprintf(stdout, "INFO: ./ dnsSpoofer [dns port]	- run with user defined dns port\n");
	fprintf(stdout, "INFO: ----------- ----------- -----------\n");
}

int SocketSetup(void)
{
	return 0;
}


int main (int argc, char *argv[])
{
	/* Application setup */
	fprintf(stdout, "DEBUG: args\n");
	for (int i = 0; i < argc; i++)
		fprintf(stdout, "DEBUG: argv[%d] - (%s)\n", i, argv[i]);

	/* check if DNS port is given */
	if (argc > 2) {
		fprintf(stderr, "ERR: unexpected user arguments!\n\n");
		usage();
		return -1;
	}

	if (argc ==2) {
		/* check if dns port number is within bounds */
		dnsPort = portCheck(argv[1], strlen(argv[1]));
		fprintf(stdout, "DEBUG: DNS port %u\n", dnsPort);
	}

	/* Socket setup */
	int ret = SocketSetup();
	if (0 == ret) {
		fprintf(stderr, "ERR: Soc ket setup failed!\n\n");
		return -4;
	}

	return 0;
}
