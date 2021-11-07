#include "dnsSpoofer_common.h"

uint16_t portCheck(char *dnsPort, size_t dnsPortLen)
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
