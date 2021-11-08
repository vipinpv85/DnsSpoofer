#include "dnsSpoof.h"

#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DNS_SPOOF_IP "14.14.14.14"
#define DNS_SPOOF_REQ "www.foo.com"
#define BUFFERSIZE 512

uint16_t dnsPort = 5300;

void usage (void)
{
	fprintf(stdout, "INFO: ----------- DNS SPOOFER (%s) -----------\n", DNS_SPOOF_IP);
	fprintf(stdout, "INFO: ./ dnsSpoofer		- default DNS port %u\n", dnsPort);
	fprintf(stdout, "INFO: ./ dnsSpoofer [dns port]	- run with user defined dns port\n");
	fprintf(stdout, "INFO: ----------- ----------- -----------\n");
}

int SocketSetup(void)
{
	int s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP);

	if (s != -1) {
		fprintf(stdout, "DEBUG: create socket (%d)\n", s);

		struct sockaddr_in dnsSock = {0};

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

	socklen_t size = sizeof(struct sockaddr_in);


		fprintf(stdout, "INFO: listening on socket - (%s-%d)\n", DNS_SPOOF_IP, dnsPort);
	do {
		unsigned char buffer[BUFFERSIZE] = {'\0'};
		struct sockaddr Client = {0};
		size = sizeof(Client);

		int ret = recvfrom(s, buffer, BUFFERSIZE, 0, (struct sockaddr*)&Client, &size);
		buffer[ret] = '\0'; 
		for (int i = 0; i < ret; i++)
		{
			fprintf(stdout, "%c ", buffer[i]);
		}


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
			fprintf(stdout, "data: (%s) \n", queryName);
		}
	} while(1);


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

	return 0;
}
