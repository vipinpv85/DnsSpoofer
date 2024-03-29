#include "dnsSpoofer_common.h"

int portCheck(char *dnsPort, size_t dnsPortLen)
{
        /* check if dns port number is within bounds */
        if ((NULL == dnsPort) || (dnsPortLen > 4) || (dnsPortLen == 0)) {
                fprintf(stderr, "ERR: dns port arguemnt is incorrect!\n\n");
                return -2;
        }

        char *digit = dnsPort;
        size_t len = dnsPortLen;

        for (int i = 0; i < len; i++, digit+= 1)
        {
                if (!isdigit(*digit)) {
                        fprintf(stderr, "ERR: dns port arguemnt is not uint16_t digits!\n\n");
                        return -3;
                }
        }

        return (uint16_t) (atoi(dnsPort) & 0xff);
}

void ChangeToDnsName (unsigned char *urlName, unsigned char* dnsName)
{
	assert((urlName != NULL) && (dnsName != NULL));

	fprintf(stdout, "DEBUG: URL NAME: (%s)\n", urlName);

	

	fprintf(stdout, "DEBUG: DNS NAME: (%s)\n", dnsName);
}

int ChangeFromDnsName (unsigned char* dnsName, unsigned char *urlName)
{
	if ((urlName == NULL) || (dnsName == NULL))
		return -1;

	bool dnsEndOfText = false; /* stop at 0 */
	uint16_t dnsPos = 0, urlPos = 0, dnsLen = strlen(dnsName);

	fprintf(stdout, "DEBUG: DNS NAME: (%s)\n", dnsName);

	do {
		if (dnsName[dnsPos] == 0) {
			dnsEndOfText = true;
			continue;
		}
		uint8_t subStringLen = (dnsName[dnsPos] & 0xff) - '0';

		dnsPos += 1;
		memcpy(&urlName[urlPos], &dnsName[dnsPos], subStringLen);
		urlPos += subStringLen;
		urlName[urlPos] = '.';
		urlPos += 1;
		urlName[urlPos] = '\0';

		dnsPos += subStringLen;
	} while ((false == dnsEndOfText) || (dnsPos < dnsLen));
	urlName[urlPos - 1] = '\0';

	fprintf(stdout, "DEBUG: URL NAME: (%s)\n", urlName);
	return ((dnsLen - dnsPos) == 0) ? dnsPos : 0;
} 
