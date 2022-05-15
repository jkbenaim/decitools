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
#include <time.h>

#include "deci.h"
#include "hexdump.h"
#include "mapfile.h"
#include "psxexe.h"

extern char *__progname;
static void noreturn usage(void);
void process_packet(uint8_t *buf, size_t recvd);

int sock;

char *bload_filename = NULL;
uint32_t bload_addr = ~0;
char *exe_filename = NULL;
uint32_t go_pc = ~0;
uint32_t go_sp = 0x801ffff0;

enum mode_e {
	MODE_IDK,
	MODE_RESET,
	MODE_BLOAD,
	MODE_RUN,
	MODE_GO,
} mode = MODE_IDK;

bool upload(uint8_t *buf, unsigned n, unsigned addr)
{
	bool rc;
	unsigned bytes_uploaded = 0;
	while (bytes_uploaded < n) {
		uint32_t chunk_size = n - bytes_uploaded;
		if (chunk_size > 0xfd4) chunk_size = 0xfd4;
		rc = idownload_send(addr + bytes_uploaded, chunk_size, buf);
		buf += chunk_size;
		bytes_uploaded += chunk_size;
		if (!rc) return false;
	}
	return true;
}

bool upload_file(char *filename, unsigned addr)
{
	struct MappedFile_s m;
	bool rc;
	m = MappedFile_Open(filename, false);
	if (!m.data) err(1, "couldn't open '%s' for reading", filename);
	if (m.size == 0) return true;

	rc = upload(m.data, m.size, addr);
	MappedFile_Close(m);
	m.data = NULL;
	return rc;
}

bool run_exe(char *filename)
{
	uint8_t *ptr = NULL;
	size_t bytes_to_upload;
	struct MappedFile_s m;
	uint32_t addr;

	m = MappedFile_Open(filename, false);
	if (!m.data) err(1, "couldn't open '%s' for reading", filename);
	ptr = (uint8_t *)m.data + 0x800;

	struct psxexe_s *exe = (struct psxexe_s *)m.data;
	if (memcmp(exe->magic, "PS-X EXE\0\0\0\0\0\0\0", 16))
		errx(1, "bad exe magic");

	bytes_to_upload = le32toh(exe->size);
	addr = le32toh(exe->vma);

	upload(ptr, bytes_to_upload, addr);


	if (!sdisp(1)) return false;
	if (!retry_send()) return false;

	return irun_send_exe(exe);
}

bool decisetup(int *argc, char **argv[])
{
	int rc;
	int port;
	struct sockaddr_in address;
	char *ip = NULL;
	char *zTmp = NULL;

	if (32 != sizeof(struct decihdr))
		errx(1, "decihdr size not 32");
	
	while ((rc = getopt(*argc, *argv, "m:")) != -1)
		switch (rc) {
		case 'm':
			if (ip)
				usage();
			ip = optarg;
			break;
		default:
			usage();
		}
	*argc -= optind;
	*argv += optind;

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
	return true;
}

bool deciloop()
{
	struct pollfd fds[1] = {0};
	uint8_t *buf = malloc(BUFSIZ);
	size_t recvd;
	fds[0].fd = sock;
	fds[0].events = POLLIN;
	fds[0].revents = 0;

	while(poll(fds, 1, -1) != -1) {
		if (fds[0].revents & POLLIN) {
			recvd = read(fds[0].fd, buf, BUFSIZ);
			if (recvd == -1) err(1, "couldn't read from sock");
			//printf("received size: %lu\n", recvd);
			unsigned cur = 0;
			struct decihdr *hdr;
			do {
				hdr = (struct decihdr *)(buf+cur);
				size_t size = le16toh(hdr->size);
				process_packet(buf+cur, size);
				cur += size;
			} while(cur < recvd);
		}
	}

	close(sock);
	return true;
}

bool exit_on_ipl = false;
bool when_iplsvc_appears()
{
	if (exit_on_ipl) exit(0);
	switch (mode) {
	case MODE_RESET:
		exit(0);
		break;
	case MODE_BLOAD:
		upload_file(bload_filename, bload_addr);
		exit_on_ipl = true;
		comstat_send();
		break;
	case MODE_RUN:
		run_exe(exe_filename);
		break;
	case MODE_GO:
		irun_send(go_pc, go_sp);
		break;	
	default:
		errx(1, "unknown mode");
		break;
	}
	return true;
}

bool when_iplsvc_disappears()
{
	switch (mode) {
	case MODE_RUN:
		exit_on_ipl = true;
		break;
	case MODE_GO:
		exit_on_ipl = true;
	default:
		break;
	}
	return true;
}

int main(int argc, char *argv[])
{
	decisetup(&argc, &argv);

	if (!strcmp(__progname, "reset15")) {
		mode = MODE_RESET;
	} else if(!strcmp(__progname, "bload15")) {
		mode = MODE_BLOAD;
	} else if (!strcmp(__progname, "run15")) {
		mode = MODE_RUN;
	} else if (!strcmp(__progname, "pgo15")) {
		mode = MODE_GO;
	} else {
		errx(1, "unknown program name");
	}
	

	switch (mode) {
	case MODE_RESET:
		reset_send(0);
		sdisp(1);
		hwconf_send();
		comstat_send();
		break;
	case MODE_RUN:
		sdisp(1);
		hwconf_send();
		comstat_send();
		exe_filename = *argv;
		break;
	case MODE_BLOAD:
		sdisp(1);
		hwconf_send();
		comstat_send();
		bload_filename = argv[0];
		bload_addr = strtoul(argv[1], NULL, 16);
		break;
	case MODE_GO:
		sdisp(1);
		hwconf_send();
		comstat_send();
		go_pc = strtoul(argv[0], NULL, 16);
		if (argc >= 2)
			go_sp = strtoul(argv[1], NULL, 16);
		break;
	default:
		errx(1, "unknown mode");
		break;
	}

	deciloop();

	return EXIT_SUCCESS;
}


void print_comstat(uint8_t *buf, size_t bodysiz)
{
	struct comstat {
		uint32_t cat;
		uint32_t pri;
		uint32_t opt;
	} __attribute__((packed));

	static bool iplsvc_appeared = false;

	struct comstat *comstat = malloc(bodysiz);
	if (!comstat) err(1, "print_comstat malloc");
	memcpy(comstat, buf, bodysiz);
	size_t ncoms = bodysiz/12;
	for (int i=0; i<ncoms; i++) {
		comstat[i].cat = le32toh(comstat[i].cat);
		comstat[i].pri = le32toh(comstat[i].pri);
		comstat[i].opt = le32toh(comstat[i].opt);
	}
	//printf("COMSTAT:\n");
	if (ncoms == 0) printf("(no categories)\n");
	bool iplsvc_appeared_this_time = false;
	for (int i=0; i<ncoms; i++) {
		const char *catname;
		switch(comstat[i].cat) {
		case CAT_TTY: catname = "TTY "; break;
		case CAT_T:   catname = "T   "; break;
		case CAT_IPL:
			catname = "IPL ";
			when_iplsvc_appears();
			iplsvc_appeared = true;
			iplsvc_appeared_this_time = true;
			break;
		case CAT_FILE: catname = "FILE"; break;
		case CAT_DBG: catname = "DBG "; break;
		default: catname = "idk "; printf("idk=%x\n", comstat[i].cat); break;
		}
#if 0
		printf("%s\t%xh\t%xh\n",
			catname,
			comstat[i].pri,
			comstat[i].opt
		);
#endif
		
	}
	if (iplsvc_appeared && !iplsvc_appeared_this_time)
		when_iplsvc_disappears();
	free(comstat);
}

void print_hwconfig(uint8_t *buf, size_t bodysiz)
{
	struct hwconfig {
		uint32_t numfields;
		uint32_t date;
		uint32_t flags;
		uint32_t sysname_len;
		uint32_t prid;
		uint32_t idk1;
		uint32_t max_pkt_size;
		uint32_t idk3;
		uint32_t idk4;
		uint32_t idk5;
		uint32_t idk6;
		uint32_t idk7;
		uint32_t idk8;
		uint32_t idk9;
		uint32_t idkA;
		uint32_t idkB;
		uint32_t idkC;
		uint32_t idkD;
		char sysname[];
	} __attribute__((packed));

	if (bodysiz < 44) {
		printf("weird hwconfig, processing aborted\n");
		hexdump(buf, bodysiz);
		return;
	}

	struct hwconfig hwconfig;
	memcpy(&hwconfig, buf, sizeof(hwconfig));
	hwconfig.numfields = le32toh(hwconfig.numfields);
	hwconfig.date = le32toh(hwconfig.date);
	hwconfig.flags = le32toh(hwconfig.flags);
	hwconfig.sysname_len = le32toh(hwconfig.sysname_len);
	hwconfig.prid = le32toh(hwconfig.prid);
	size_t size_from_packet = 4*(hwconfig.numfields+1) + hwconfig.sysname_len;
	if (size_from_packet != bodysiz) {
		printf("weird hwconfig, processing aborted\n");
		hexdump(buf, bodysiz);
		return;
	}
	char *sysname = (char *)calloc(1, hwconfig.sysname_len);
	if (!sysname) err(1, "hwconfig malloc");
	memcpy(sysname, buf + 0x44, hwconfig.sysname_len);
	for (int i=0; i<hwconfig.sysname_len; i++) {
		if ((sysname[i] < ' ') || (sysname[i] > '~')) {
			sysname[i] = '\0';
			break;
		}
	}

	printf( " << PS ROM %08x-%08x >> %s\n",
		hwconfig.date,
		hwconfig.flags,
		sysname
	);
	//hexdump(&hwconfig, sizeof(hwconfig));
	free(sysname);
}

void print_getinfo(uint8_t *buf, size_t bodysiz)
{
	struct zgetinfo_body_s *body = (struct zgetinfo_body_s *)buf;
	printf("GETINFO: deciflags: %xh, innerqueue: %xh\n",
		le32toh(body->deciflags),
		le32toh(body->innerqueue)
	);
	//hexdump(buf, bodysiz);
}

void fopen_handle(struct decipkt *pkt)
{
	struct fopen_body_s *body = pkt->body;
	char *name = calloc(le32toh(body->namesize) + 1, 1);
	if (!name) err(1, "malloc failure");
	memcpy(name, body->name, le32toh(body->namesize));
	printf("file open request: %s\n", name);
	free(name);
	myacknak(pkt->hdr.tag, 0);
}

void process_packet(uint8_t *buf, size_t recvd)
{
	if (recvd < 0x20) return;
	struct decihdr *hdr = (struct decihdr *)buf;
	size_t len = le16toh(hdr->size);
	struct decipkt *pkt = new_packet(len - 0x20);
	memcpy(&pkt->hdr, buf, 0x20);
	pkt->body = buf + 0x20;
	pkt_ntoh(pkt);
	switch (pkt->hdr.req) {
	case REQ_ZACKNAK:
		// TODO
		//printf("acknak\n");
		break;
	case REQ_ZHWCONFIG:
		print_hwconfig(pkt->body, len - 0x20);
		break;
	case REQ_ZCOMSTAT:
		print_comstat(pkt->body, len - 0x20);
		break;
	case REQ_SSEND:
		//printf("ssend\n");
		write(1, pkt->body, pkt->hdr.size - 0x20);
		myacknak(pkt->hdr.tag, 0);
		break;
	case REQ_ZPANICMSG:
		fprintf(stderr, "target panic: ");
		fwrite(pkt->body, len - 0x20, 1, stderr);
		exit(0);
		break;
	case REQ_ZGETINFO:
		print_getinfo(pkt->body, len - 0x20);
		break;
	case REQ_FOPEN:
		fopen_handle(pkt);
		break;
	case 0x44810000:
		printf("4481 again\n");
		hexdump(buf, recvd);
		myacknak(pkt->hdr.tag, 0);
		d_idk_send(0);
		break;
	default:
		printf("unknown packet request %08x\n", pkt->hdr.req);
		hexdump(buf, recvd);
		myacknak(pkt->hdr.tag, 0);
		break;
	}
	free(pkt);
}

static void noreturn usage(void)
{
	(void)fprintf(stderr, "usage: %s -m machine\n",
		__progname
	);
	exit(EXIT_FAILURE);
}
