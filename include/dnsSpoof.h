#ifndef _DNS_SPOOF_CHECK_
#define _DNS_SPOOF_CHECK_

#include <inttypes.h>
#include <stddef.h>

/* from https://datatracker.ietf.org/doc/html/rfc1035 section 4.1.1 */
/*
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
typedef struct dnsHeader_s 
{
	uint16_t id;
	uint8_t rd :1;
	uint8_t tc :1;
	uint8_t aa :1;
	uint8_t opcode :4;
	uint8_t qr :1;
	uint8_t rcode :4;
	uint8_t cd :1;
	uint8_t ad :1;
	uint8_t z :1;
	uint8_t ra :1;
	uint16_t q_count;
	uint16_t ans_count;
	uint16_t auth_count;
	uint16_t add_count;
} __attribute__((packed)) dnsHeader_t;


uint16_t portCheck(char *dnsPort, size_t dnsPortLen);

#endif
