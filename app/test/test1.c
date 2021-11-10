#include "dnsSpoof.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int dns_portCheck(char *dnsPort, size_t dnsPortLen)
{
	int32_t Port = portCheck(dnsPort, dnsPortLen);
	return ((Port > 0) ? 1 : 0);
}

int dns_ChangeFromDnsName(unsigned char* dnsName, int valid)
{
	char url[512] = {'\0'};
	int32_t dnsPos = 0;

	printf("dnsName %s dnsPos %d urlName %s\n", dnsName, dnsPos, url);
	dnsPos = ChangeFromDnsName(dnsName, (valid) ? url : NULL);
	printf("dnsName %s dnsPos %d urlName %s\n", dnsName, dnsPos, url);
	return (dnsPos > 0)? 1 : 0;
}

int main(int argc, char *argv[])
{
	/* Application setup */
	printf("DEBUG: args\n");
	for (int i = 0; i < argc; i++)
		printf("DEBUG: argv[%d] - (%s)\n", i, argv[i]);

	if (argc != 5)
		return -1;

	int expectedResult = atoi(argv[1]);
	int isPortCheck = !strncmp("portCheck", argv[2], 8);
	int isChangeFromDnsName = !strncmp("ChangeFromDnsName", argv[2], 8);

	printf(" expectedResult %d isPortCheck %d isChangeFromDnsName %d\n", expectedResult, isPortCheck, isChangeFromDnsName);

	if ((isPortCheck == 0) && (isChangeFromDnsName == 0))
		return -2;

	if (isPortCheck) {
		int isNull = !strncmp("NULL", argv[3], 4);
		if (expectedResult != dns_portCheck(isNull ? NULL : argv[3], atoi(argv[4])))
			return -3;
	}

	if (isChangeFromDnsName) {
		int isValid = !strncmp("valid", argv[4], 5);

		printf(" isValid %d\n", isValid);
		if (expectedResult != dns_ChangeFromDnsName(argv[3], isValid))
			return -3;
	}

	return 0;
}
