#include "dnsSpoof.h"

#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DNS_SPOOF_IP (0x05050505)
#define DNS_SPOOF_REQ "www.foo.com"
#define BUFFERSIZE 512

uint16_t dnsPort = 5300;
struct sockaddr_in dnsSock = {0};

void usage (void)
{
	fprintf(stdout, "INFO: ----------- DNS SPOOFER (0x%x) -----------\n", DNS_SPOOF_IP);
	fprintf(stdout, "INFO: ./ dnsSpoofer		- default DNS port %u\n", dnsPort);
	fprintf(stdout, "INFO: ./ dnsSpoofer [dns port]	- run with user defined dns port\n");
	fprintf(stdout, "INFO: ----------- ----------- -----------\n");
}

void processDns(int s)
{
	socklen_t size = sizeof(struct sockaddr_in);

	fprintf(stdout, "INFO: listening on socket - (0x%x-%d)\n", DNS_SPOOF_IP, dnsPort);
	do {
		unsigned char buffer[BUFFERSIZE] = {0};

		struct sockaddr Client = {0};
		size = sizeof(Client);

		int ret = recvfrom(s, buffer, BUFFERSIZE, 0, (struct sockaddr*)&Client, &size);
		buffer[ret] = '\0'; 

		dnsHeader_t *dnsPtr = (dnsHeader_t *)buffer;
		fprintf(stdout, "\n--------------\n");
		fprintf(stdout, "DBG: id (%u)\n", ntohs(dnsPtr->id));
		fprintf(stdout, "DBG: recursion desired (%u)\n", dnsPtr->rd);
		fprintf(stdout, "DBG: truncated message (%u)\n", dnsPtr->tc);
		fprintf(stdout, "DBG: authorative answer (%u)\n", dnsPtr->aa);
		fprintf(stdout, "DBG: opcode (%u)\n", dnsPtr->opcode);
		fprintf(stdout, "DBG: query|response (%s)\n", (dnsPtr->qr)?"reply":"query");
		fprintf(stdout, "DBG: response code (%u)\n", dnsPtr->rcode);
		fprintf(stdout, "DBG: question count (%u)\n", ntohs(dnsPtr->q_count));
		fprintf(stdout, "DBG: answer record count (%u)\n", ntohs(dnsPtr->ans_count));
		fprintf(stdout, "DBG: name server record count (%u)\n", ntohs(dnsPtr->auth_count));
		fprintf(stdout, "DBG: additional record count (%u)\n", ntohs(dnsPtr->add_count));

		if (0 == dnsPtr->qr) {
			unsigned char *queryName = &buffer[sizeof(dnsHeader_t)];
			uint16_t offsetPos = 0;
			unsigned char url[512];
			unsigned char query[512];

			for (int i = 0; i < ntohs(dnsPtr->q_count); i++)
			{
				fprintf(stdout, "query data: (%s) \n", queryName);
				offsetPos += ChangeFromDnsName(queryName, url);
			}

			/* copy the query to seperate buffer for future use */
			memcpy(&query, queryName, offsetPos + 1 + sizeof(dnsQuestion_t));

			dnsQuestion_t *qPtr = (dnsQuestion_t *)((unsigned char *) &buffer[sizeof(dnsHeader_t)] + offsetPos + 1);
			fprintf(stdout, " DBG: qtype: 0x%02x qclass: 0x%02x\n", ntohs(qPtr->qtype), ntohs(qPtr->qclass));

			fprintf(stdout, " DBG: additional record %ld\n", ret - (sizeof(dnsHeader_t) + offsetPos + 1));
			//for (int i = sizeof(dnsHeader_t) + offsetPos + 1; i < ret; i++)
			//	fprintf(stdout, "0x%02x ", buffer[i]);

			if ((1 == ntohs(qPtr->qtype)) && (1 == ntohs(qPtr->qclass))) {
				/* https://www.cloudshark.org/captures/56802b91286a for reply */

				//for (int i = 0; i < (offsetPos + 1 + sizeof(dnsQuestion_t)); i++)
				//	fprintf(stdout, " -- 0x%02x ", query[i]);

				/* prepare reply */
				dnsPtr->qr = 1; /* reply */

				/* prepare reply with answer after DNS header and query */
				dnsResponse_t *answer = (dnsResponse_t *)&buffer[sizeof(dnsHeader_t) + offsetPos + 1];
				answer->name = htons(0xc00c); /* compressed name */
				answer->type = htons(0x01);
				answer->classtype = htons(0x01);
				answer->ttl = htonl(0x01);
				answer->data_len = htons(0x04);

				/* append IP address */
				*(uint32_t *)(answer + 1) = htonl(DNS_SPOOF_IP);

				for (int i = 0; i < (sizeof(dnsHeader_t) + offsetPos + 1 + sizeof(dnsQuestion_t) + sizeof(dnsResponse_t) + 4); i++)
					fprintf(stdout, " 0x%02x ", buffer[i]);

				fprintf(stdout, "DBG: Sending DNS reply for (%s)...\n", url);
				if(sendto(s,(char*)buffer,
					(sizeof(dnsHeader_t) + offsetPos + 1 + sizeof(dnsQuestion_t) + sizeof(dnsResponse_t) + 4),
					0, (const struct sockaddr *)&dnsSock, sizeof(dnsSock)) < 0) {
					fprintf(stderr, "ERR: failed to send response!\n");
					return;
				}
			}
		}
	} while(1);
}

int SocketSetup(void)
{
	int s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP);

	if (s != -1) {
		fprintf(stdout, "DEBUG: create socket (%d)\n", s);


		dnsSock.sin_family = AF_INET;
		dnsSock.sin_port = htons(dnsPort);
		dnsSock.sin_addr.s_addr = inet_addr("10.190.210.151");
		dnsSock.sin_addr.s_addr = INADDR_ANY;

		int enable = 1;
		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
			fprintf(stderr, "ERR: setsockopt(SO_REUSEADDR) failed\n");
			return 0;
		}

		/* Bind the socket with the server address */
		if ( bind(s, (const struct sockaddr *)&dnsSock, sizeof(dnsSock)) < 0 ) {
			fprintf(stdout, "ERR: bind failed");
			return 0;
		}


		return s;
	}
	
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
	int sock = SocketSetup();
	if (0 == sock) {
		fprintf(stderr, "ERR: Socket setup failed!\n\n");
		return -4;
	}

	processDns(sock);
	return 0;
}
