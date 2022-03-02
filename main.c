#include <arpa/inet.h>
#include <endian.h>
#include <err.h>
#include <inttypes.h>
#include <iso646.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "deci.h"
#include "hexdump.h"

extern char *__progname;
static void noreturn usage(void);

int sock;

int main(int argc, char *argv[])
{
	int rc;
	int port;
	struct sockaddr_in address;
	char *ip = NULL;
	char *zTmp = NULL;
	struct pollfd fds[1] = {0};

	if (32 != sizeof(struct decihdr))
		errx(1, "decihdr size not 32");
	
	while ((rc = getopt(argc, argv, "m:")) != -1)
		switch (rc) {
		case 'm':
			if (ip)
				usage();
			ip = optarg;
			break;
		default:
			usage();
		}
	argc -= optind;
	argv += optind;
	if (*argv != NULL)
		usage();

	// get target ip
	if (ip == NULL) {
		ip = getenv("H1500");
	}
	if (ip == NULL) {
		errx(1, "must specify machine with either the -m option, or the H1500 environment variable");
	}

	// get target port
	zTmp = getenv("H1500PORT");
	if (zTmp != NULL) {
		port = strtoul(zTmp, NULL, 10);
		if (port == 0) err(1, "invalid value for H1500PORT");
	} else {
		port = 8155;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) err(1, "couldn't open socket");

	memset(&address, '0', sizeof(address));
	address.sin_family = AF_INET;
	address.sin_port = htons(port);
	if (inet_pton(AF_INET, ip, &address.sin_addr) <= 0)
		err(1, "bad ip");
	
	if (connect(sock, (struct sockaddr *)&address,
		sizeof(address)) < 0)
		err(1, "couldn't connect");
	
	// WHATEVER GOES HERE
	reset_send(1);
	//sdisp(0);
	//comstat_send();
	//hwconf_send();
	//retry_send();
	//idk_send();
	
	fds[0].fd = sock;
	fds[0].events = POLLIN;
	fds[0].revents = 0;

	uint8_t *buf = malloc(BUFSIZ);
	size_t recvd;
	void process_packet(uint8_t *buf, size_t recvd);
	while(poll(fds, 1, -1) != -1) {
		if (fds[0].revents & POLLIN) {
			recvd = read(fds[0].fd, buf, BUFSIZ);
			if (recvd == -1) err(1, "couldn't read from sock");
			unsigned cur = 0;
			struct decihdr *hdr;
			do {
				process_packet(buf+cur, recvd);
				hdr = (struct decihdr *)(buf+cur);
				cur += le32toh(hdr->size);
			} while(cur < recvd);
		}
		//sleep(1);
	}

	close(sock);

	return EXIT_SUCCESS;
}

void process_packet(uint8_t *buf, size_t recvd)
{
	struct decipkt *pkt = new_packet(recvd - 0x20);
	memcpy(&pkt->hdr, buf, 0x20);
	pkt->body = buf + 0x20;
	pkt_ntoh(pkt);
	switch (pkt->hdr.req) {
	case REQ_ZACKNAK:
		// TODO
		break;
	case REQ_ZHWCONFIG:
		printf("hwconfig\n");
		break;
	case REQ_ZCOMSTAT:
		printf("comstat\n");
		break;
	case REQ_SSEND:
		//printf("ssend\n");
		write(1, pkt->body, pkt->hdr.size - 0x20);
		myacknak(pkt->hdr.tag, 0);
		break;
	default:
		printf("unknown packet request %08x\n", pkt->hdr.req);
		break;
	}
	//hexdump(buf, recvd);
	free(pkt);
}

static void noreturn usage(void)
{
	(void)fprintf(stderr, "usage: %s -m machine\n",
		__progname
	);
	exit(EXIT_FAILURE);
}
