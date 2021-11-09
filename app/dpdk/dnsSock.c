/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include "dnsSpoof.h"

#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define DNS_SPOOF_IP (0x05050505)
uint16_t dnsPort = 5300;

/* Configuration of ethernet ports. 8<  */
static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
	},
};
/* >8 End of configuration of ethernet ports. */

/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

void usage (void)
{
        fprintf(stdout, "INFO: ----------- DNS SPOOFER (0x%x) -----------\n", DNS_SPOOF_IP);
        fprintf(stdout, "INFO: ./ dnsSpoofer            - default DNS port %u\n", dnsPort);
        fprintf(stdout, "INFO: ./ dnsSpoofer [dns port] - run with user defined dns port\n");
        fprintf(stdout, "INFO: ----------- ----------- -----------\n");
}


/* Main functional part of port initialization. 8< */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Starting Ethernet port. 8< */
	retval = rte_eth_dev_start(port);
	/* >8 End of starting of ethernet port. */
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	/* End of setting RX port in promiscuous mode. */
	if (retval != 0)
		return retval;

	return 0;
}
/* >8 End of main functional part of port initialization. */

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

int dnsProcessPacket(struct rte_mbuf *buf)
{
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;

	eth_hdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
	ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

	/* todo: 
		rte_is_same_ether_add rte_is_zero_ether_addr rte_is_multicast_ether_addr rte_is_broadcast_ether_addr 
		rte_vlan_strip
         */

	if (eth_hdr->ether_type == 0x08) {
		/* 
		  todo:
			fetch actual header size rte_ipv4_hdr_len
			since no offload execute rte_raw_cksum_mbuf and rte_ipv4_udptcp_cksum_verify
		 */

		if ((ipv4_hdr->next_proto_id == 17) &&
			(ipv4_hdr->time_to_live > 2) &&
			(!(ipv4_hdr->fragment_offset & (RTE_IPV4_HDR_OFFSET_MASK | RTE_IPV4_HDR_MF_FLAG)))) {
			struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *) (ipv4_hdr + 1);

			if (udp_hdr->dst_port == ntohs(dnsPort)) {
		                dnsHeader_t *dnsPtr = (dnsHeader_t *) (udp_hdr + 1);
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

                		if ((0 == dnsPtr->qr) && (1 == ntohs(dnsPtr->q_count))) {
					unsigned char *queryName = (unsigned char *) &dnsPtr[sizeof(dnsHeader_t)];
					uint16_t offsetPos = 0;
					unsigned char url[512];
					unsigned char query[512];

                                	fprintf(stdout, "query data: (%s) \n", queryName);
					offsetPos += ChangeFromDnsName(queryName, url);

                		        /* copy the query to seperate buffer for future use */
		                        memcpy(&query, queryName, offsetPos + 1 + sizeof(dnsQuestion_t));

		                        dnsQuestion_t *qPtr = (dnsQuestion_t *)((unsigned char *)queryName + offsetPos + 1);

		                        fprintf(stdout, " DBG: qtype: 0x%02x qclass: 0x%02x\n", ntohs(qPtr->qtype), ntohs(qPtr->qclass));

					if ((1 == ntohs(qPtr->qtype)) && (1 == ntohs(qPtr->qclass))) {
        	        	                /* prepare reply */
	        	                        dnsPtr->qr = 1; /* reply */

		                                /* prepare reply with answer after DNS header and query */
                		                dnsResponse_t *answer = (dnsResponse_t *) qPtr;
                                		answer->name = htons(0xc00c); /* compressed name */
		                                answer->type = htons(0x01);
		                                answer->classtype = htons(0x01);
		                                answer->ttl = htonl(0x01);
                		                answer->data_len = htons(0x04);

						/* append IP address */
						*(uint32_t *)(answer + 1) = htonl(DNS_SPOOF_IP);

						/* update dpdk paramaters */
						buf->data_len = buf->pkt_len = 	sizeof(struct rte_ether_hdr) +
										sizeof(struct rte_ipv4_hdr ) +
										sizeof(struct rte_udp_hdr) +
										sizeof(dnsHeader_t) + offsetPos + 1 + sizeof(dnsResponse_t) + 4;
					}
				}
			}
		}
	}

	return 0;
}

 /* Basic forwarding application lcore. 8< */
static __rte_noreturn void
lcore_main(void)
{
	uint16_t port;

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) >= 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());

	/* Main work of application loop. 8< */
	for (;;) {
		/*
		 * Receive packets on a port and forward them on the paired
		 * port. The mapping is 0 -> 1, 1 -> 0, 2 -> 3, 3 -> 2, etc.
		 */
		RTE_ETH_FOREACH_DEV(port) {

			/* Get burst of RX packets, from first port of pair. */
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);

			if (unlikely(nb_rx == 0))
				continue;

			for (int i = 0; i < nb_rx; i++)
			{
				struct rte_mbuf *buf = bufs[i];

				if (dnsProcessPacket(buf) == 1) {
					if (likely(rte_eth_tx_burst(port, 0, &buf, 1)))
						continue;
				}

				rte_pktmbuf_free(buf);
			}
		}
	}
	/* >8 End of loop. */
}
/* >8 End Basic forwarding application lcore. */

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;

	/* Initializion the Environment Abstraction Layer (EAL). 8< */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	/* >8 End of initializion the Environment Abstraction Layer (EAL). */

	argc -= ret;
	argv += ret;

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

        if (argc == 2) {
                /* check if dns port number is within bounds */
                dnsPort = portCheck(argv[1], strlen(argv[1]));
                fprintf(stdout, "DEBUG: DNS port %u\n", dnsPort);
        }

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports != 1)
		rte_exit(EXIT_FAILURE, "Error: number of ports must be one\n");

	/* Creates a new mempool in memory to hold the mbufs. */

	/* Allocates mempool to hold the mbufs. 8< */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	/* >8 End of allocating mempool to hold mbuf. */

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initializing all ports. 8< */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);
	/* >8 End of initializing all ports. */

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the main core only. Called on single lcore. 8< */
	lcore_main();
	/* >8 End of called on single lcore. */

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
