#include "dnsSpoof.h"

#include <stdio.h>

int dns_portCheck(char *dnsPort, size_t dnsPortLen)
{
	uint16_t Port = portCheck(dnsPort, dnsPortLen);

	return ((Port) ? 0 : -1);
}

int dns_ChangeFromDnsName(unsigned char* dnsName, unsigned char *urlName)
{
	uint16_t dnsPos = ChangeFromDnsName(dnsName, urlName);
	return ((dnsPos >= 3) ? 0 : -1);
}

int main(int argc, char *argv[])
{
	/* Application setup */
	printf("DEBUG: args\n");
	for (int i = 0; i < argc; i++)
		printf("DEBUG: argv[%d] - (%s)\n", i, argv[i]);

	return 0;
}
