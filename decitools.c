#ifdef __MINGW32__
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/poll.h>
#include <sys/socket.h>
#endif
#include "endian.h"
#include "err.h"
#include "errnet.h"
#include <inttypes.h>
#include <iso646.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "deci.h"
#include "hexdump.h"
#include "mapfile.h"
#include "psxexe.h"
#include "intl.h"

#ifdef __MINGW32__
char *__progname;
#else
extern char *__progname;
#endif

static void noreturn usage(void);
void process_packet(uint8_t *buf, size_t recvd);

#ifdef __MINGW32__
unsigned sock;
#else
int sock;
#endif

char *bload_filename = NULL;
uint32_t bload_addr = ~0;
char *exe_filename = NULL;
uint32_t go_pc = ~0;
uint32_t go_sp = 0x801ffff0;
char *setrun_name = NULL;

enum mode_e {
	MODE_IDK,
	MODE_RESET,
	MODE_BLOAD,
	MODE_RUN,
	MODE_GO,
	MODE_SETRUN,
	MODE_MEMREAD,
	MODE_GETREG,
	MODE_PSCOMUTIL,
} mode = MODE_IDK;

bool packet_pump();

#ifdef __MINGW32__
void term_normal()
{
	HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(h,
		FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_BLUE);
}
void term_whisper()
{
	HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(h, FOREGROUND_INTENSITY);
}
#else
void term_normal()	{printf("\e[0m");}
void term_whisper()	{printf("\e[02m");}
#endif

bool upload(uint8_t *buf, unsigned n, unsigned addr)
{
	bool rc;
	unsigned bytes_uploaded = 0;
	unsigned progress = 0;
	unsigned oldprogress = 0;

	term_whisper();
	printf("(uploading");
	fflush(stdout);

	while (bytes_uploaded < n) {
		uint32_t chunk_size = n - bytes_uploaded;
		if (chunk_size > 0xfd4) chunk_size = 0xfd4;
		rc = idownload_send(addr + bytes_uploaded, chunk_size, buf);
		buf += chunk_size;
		bytes_uploaded += chunk_size;
		if (!rc) return false;
		term_normal();
		packet_pump();
		term_whisper();
		progress = 10*bytes_uploaded / n;
		if (progress > oldprogress) {
			for (unsigned i = 0; i < (progress - oldprogress); i++)
				printf(".");
			fflush(stdout);
			oldprogress = progress;
		}
	}
	printf(" done.)\n");
	term_normal();
	fflush(stdout);
	return true;
}

bool upload_file(char *filename, unsigned addr)
{
	struct MappedFile_s m;
	bool rc;
	m = MappedFile_Open(filename, false);
	if (!m.data) err(1, _("couldn't open '%s' for reading"), filename);
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
	if (!m.data) err(1, _("couldn't open '%s' for reading"), filename);
	ptr = (uint8_t *)m.data + 0x800;

	struct psxexe_s *exe = (struct psxexe_s *)m.data;
	if (memcmp(exe->magic, "PS-X EXEa", 8))
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
		errx(1, _("must specify machine with either the -m option, or the H1500 environment variable"));
	}

	// get target port
	zTmp = getenv("H1500PORT");
	if (zTmp != NULL) {
		port = strtoul(zTmp, NULL, 10);
		if (port == 0) err(1, _("invalid value for H1500PORT"));
	} else {
		port = 8155;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
#ifdef __MINGW32__
	if (sock == INVALID_SOCKET)
		errx(1, _("couldn't open socket: %d"), WSAGetLastError());
#else
	if (sock < 0)
		err(1, _("couldn't open socket"));
#endif
	memset(&address, '0', sizeof(address));
	address.sin_family = AF_INET;
	address.sin_port = htons(port);
#ifdef __MINGW32__
	unsigned long ulAddr = inet_addr(ip);
	if ((ulAddr == INADDR_NONE)
		|| (ulAddr == INADDR_ANY))
		err(1, _("couldn't parse IP address"));
	address.sin_addr.S_un.S_addr = ulAddr;
#else
	if (inet_pton(AF_INET, ip, &address.sin_addr) <= 0)
		err(1, _("couldn't parse IP address"));
#endif
	if (connect(sock, (struct sockaddr *)&address,
		sizeof(address)) < 0)
		errnet(1, _("couldn't connect to H1500"));
	return true;
}

uint8_t buf[BUFSIZ];

bool packet_pump()
{
	size_t recvd;
	recvd = recv(sock, buf, BUFSIZ, 0);
	//if (recvd == -1) err(1, _("couldn't read from socket"));
	unsigned cur = 0;
	struct decihdr *hdr;
	do {
		hdr = (struct decihdr *)(buf+cur);
		size_t size = le16toh(hdr->size);
		process_packet(buf+cur, size);
		cur += size;
	} while(cur < recvd);
	return true;
}

bool deciloop()
{
#ifdef __MINGW32__
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(sock, &fds);
#else
	struct pollfd fds[1] = {0};
	fds[0].fd = sock;
	fds[0].events = POLLIN;
	fds[0].revents = 0;
#endif

#ifdef __MINGW32__
	while(select(1, &fds, NULL, NULL, NULL) != SOCKET_ERROR) {
#else
	while(poll(fds, 1, -1) != -1) {
#endif
		packet_pump();
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
		//tdbgon_send();
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
	case MODE_SETRUN:
		isetbootname_send(setrun_name);
		break;
	case MODE_MEMREAD:
		break;
	case MODE_GETREG:
		break;
	case MODE_PSCOMUTIL:
		break;
	default:
		errx(1, _("unknown program mode"));
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
		break;
	case MODE_SETRUN:
		exit_on_ipl = true;
		break;
	case MODE_PSCOMUTIL:
		exit_on_ipl = true;
		break;
	default:
		break;
	}
	return true;
}

int main(int argc, char *argv[])
{
#ifdef __MINGW32__
	int rc;
	char *temp;
	WSADATA wsaData;
	WORD wVersionRequested = MAKEWORD(2, 2);
	rc = WSAStartup(wVersionRequested, &wsaData);
	if (rc)
		errnet(1, _("couldn't initialize Windows Sockets"));
	__progname = strrchr(argv[0], '\\');
	if (!__progname) __progname = argv[0];
	else __progname++;
	temp = strrchr(argv[0], '.');
	if (temp) temp[0] = '\0';
#endif
	decisetup(&argc, &argv);

	if (!strcmp(__progname, "reset15")) {
		mode = MODE_RESET;
	} else if(!strcmp(__progname, "bload15")) {
		mode = MODE_BLOAD;
	} else if (!strcmp(__progname, "run15")) {
		mode = MODE_RUN;
	} else if (!strcmp(__progname, "pgo15")) {
		mode = MODE_GO;
	} else if (!strcmp(__progname, "setrun15")) {
		mode = MODE_SETRUN;
	} else if (!strcmp(__progname, "memread")) {
		mode = MODE_MEMREAD;
	} else if (!strcmp(__progname, "getreg")) {
		mode = MODE_GETREG;
	} else if (!strcmp(__progname, "pscomutil")) {
		mode = MODE_PSCOMUTIL;
	} else {
		errx(1, _("unknown program name"));
	}
	
	switch (mode) {
	case MODE_RESET:
		reset_send(2);
		//tdbgon_send();
		sdisp(1);
		hwconf_send();
		comstat_send();
		//getinfo_send();
		break;
	case MODE_RUN:
		sdisp(1);
		hwconf_send();
		comstat_send();
		//tdbgon_send();
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
	case MODE_SETRUN:
		sdisp(1);
		hwconf_send();
		comstat_send();
		setrun_name = argv[0];
		break;
	case MODE_MEMREAD:
		sdisp(1);
		hwconf_send();
		comstat_send();
	{
		uint32_t size = 16;
		void *buf = malloc(size);
		if (!buf) err(1, "malloc failure");
		dmemread_send(buf, size, 0x80000000);
	}
		break;
	case MODE_GETREG:
		//sdisp(1);
		tdbgon_send();
		//hwconf_send();
		//comstat_send();
		//dgetreg_send(1,2);
		//tpalntsc_send(0);
		//dcontinue_send(0);
		//dmemread_send(NULL, 0x1000, 0xbfc00000);
		break;
	case MODE_PSCOMUTIL:
		reset_send(2);
		sdisp(1);
		hwconf_send();
		comstat_send();
		break;
	default:
		errx(1, _("unknown program mode"));
		break;
	}

	deciloop();

	return EXIT_SUCCESS;
}


void print_comstat(uint8_t *buf, size_t bodysiz)
{
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
			iplsvc_appeared = true;
			iplsvc_appeared_this_time = true;
			when_iplsvc_appears();
			break;
		case CAT_FILE: catname = "FILE"; break;
		case CAT_DBG: catname = "DBG "; break;
		default: catname = "idk "; printf("idk=%x\n", comstat[i].cat); break;
		}
#if 1
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
	const char *fieldnames[] = {
		"rom date",
		"rom type",
		"rom name len",
		"cpu type",
		"board id",
		"ram size",
		"gpu type",
		"vram size",
		"spu type",
		"spu ram size",
		"debugger type",
		"host if type",
		"pad present",
		"memcard present",
		"cdrom present",
		"host bufsize",
	};
	if (bodysiz < 44) {
		printf(_("weird hwconfig, processing aborted\n"));
		hexdump(buf, bodysiz);
		return;
	}

	struct hwconfig hwconfig;
	memcpy(&hwconfig, buf, sizeof(hwconfig));
	for (unsigned i = 0; i < 16; i++) {
		hwconfig.fields[i] = le32toh(hwconfig.fields[i]);
	}

	size_t size_from_packet = 4*(hwconfig.numfields+1) + hwconfig.romname_len;
	if (size_from_packet != bodysiz) {
		printf(_("weird hwconfig, processing aborted\n"));
		hexdump(buf, bodysiz);
		return;
	}
	char *romname = (char *)calloc(1, hwconfig.romname_len);
	if (!romname) err(1, "hwconfig malloc");
	memcpy(romname, buf + 0x44, hwconfig.romname_len);
	for (int i=0; i<hwconfig.romname_len; i++) {
		if ((romname[i] < ' ') || (romname[i] > '~')) {
			romname[i] = '\0';
			break;
		}
	}

	printf( " << PS ROM %08x-%08x >>  %s\n",
		hwconfig.romdate,
		hwconfig.romtype,
		romname
	);
	term_whisper();
	for (unsigned i = 3; i<0x10; i++) {
		printf("%s\t%-8u\n", fieldnames[i], hwconfig.fields[i]);
	}
	term_normal();
	fflush(stdout);
	free(romname);
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
	printf(_("received file open request: %s\n"), name);
	free(name);
	myacknak(pkt->hdr.tag, 0);
}

void print_dhalt(struct dhalt_body_s *body)
{
	uint32_t haltcode = le32toh(body->haltcode);
	term_whisper();
	switch (haltcode) {
	case 0:
		printf("DECI debugger start.\n");
		break;
	case 1:
		printf("User program terminated by return.\n");
		break;
	case 2:
		printf("User program terminated by exit().\n");
		break;
	case 3:
		printf("User program break by Dbreak (polling mode).\n");
		break;
	case 4:
		printf("User program break by Dbreak (interrupt mode).\n");
		break;
	case 5:
		printf("CD BOOT pause.\n");
		break;
	case 6:
		printf("User program break by Debug exception.\n");
		break;
	default:
		printf("Halt: %xh.\n", haltcode);
		dgetreg_send(0,0);
		break;
	}
	term_normal();
	fflush(stdout);
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
		fprintf(stderr, _("target panic: "));
		fwrite(pkt->body, len - 0x20, 1, stderr);
		exit(0);
		break;
	case REQ_ZGETINFO:
		print_getinfo(pkt->body, len - 0x20);
		break;
	case REQ_FOPEN:
		fopen_handle(pkt);
		break;
	case REQ_DHALT:
		myacknak(pkt->hdr.tag, 0);
		print_dhalt(pkt->body);
		break;
	case REQ_DGETREG:
		printf("dgetreg:\n");
		hexdump(buf, recvd);
		//myacknak(pkt->hdr.ackcode, 0);
		break;
	default:
		printf(_("unknown packet request %08x\n"), pkt->hdr.req);
		hexdump(buf, recvd);
		myacknak(pkt->hdr.tag, 0);
		break;
	}
	free(pkt);
}

static void noreturn usage(void)
{
	(void)fprintf(stderr, _("usage: %s -m machine\n"),
		__progname
	);
	exit(EXIT_FAILURE);
}
