#ifndef _DNS_SPOOF_CHECK_
#define _DNS_SPOOF_CHECK_

#include <inttypes.h>
#include <stddef.h>

#ifdef __cplusplus
 extern "C" {
 #endif

/* from https://datatracker.ietf.org/doc/html/rfc1035 section 4.1.1 */


/*
	General Format:

    +---------------------+
    |        Header       |
    +---------------------+
    |       Question      | the question for the name server
    +---------------------+
    |        Answer       | RRs answering the question
    +---------------------+
    |      Authority      | RRs pointing toward an authority
    +---------------------+
    |      Additional     | RRs holding additional information
    +---------------------+
 */

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

/*
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
typedef struct dnsQuestion_s
{
	unsigned short qtype;
	unsigned short qclass;
} dnsQuestion_t;

/*
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
typedef struct dnsResponse_s
{
	unsigned short name;
	unsigned short type;
	unsigned short classtype;
	unsigned int ttl;
	unsigned short data_len;
} __attribute__((packed)) dnsResponse_t;

/**
 * Check DNS port shared from the user. it coverts user input into UDP port.
 * 
 * @return return uint16_t UDP port. for invalid it return 0
 *
 * @param dnsPort
 * The *dnsPort* pointer is the address of the DNS port string.
 * @param dnsPortLen
 * The *dnsPortLen* is the size of dnsPort.
 */
int portCheck(char *dnsPort, size_t dnsPortLen);

/**
 * converts given DNS name into actual string. 
 *
 * return 0 for invalid and actual position from DNS name
 *
 * @param dnsName
 * The *dnsName* input shared to convert
 * @param urlName
 * The *urlName* converted from dnsName
 */
int ChangeFromDnsName(unsigned char* dnsName, unsigned char *urlName);

 #ifdef __cplusplus
 }
 #endif

#endif
