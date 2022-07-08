#ifdef __MINGW32__
#else
#include <sys/socket.h>
#endif
#include "endian.h"
#include "err.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "deci.h"
#include "hexdump.h"
#include "intl.h"
#include "errnet.h"

#ifdef __MINGW32__
extern unsigned sock;
#else
extern int sock;
#endif

struct decipkt *send_queue[100];
struct decipkt *wait_queue[100];
int num_send_queue;
int num_wait_queue;
int packetsize;
int needhwconf;
int timeoutval;

struct decipkt *new_packet(size_t body_size)
{
	struct decipkt *pkt = calloc(sizeof(struct decipkt), 1);
	if (pkt == NULL) err(1, N_("new_packet malloc"));
	if (body_size != 0) {
		pkt->body = calloc(body_size, 1);
		if (pkt->body == NULL) err(1, "new_packet body malloc");
	}
	pkt->hdr.magic = DECI_MAGIC;
	pkt->hdr.size = sizeof(struct decihdr) + body_size;
	return pkt;
}

void delete_packet(struct decipkt *pkt)
{
	if (pkt)
		free(pkt->body);
	free(pkt);
}

void pkt_hton(struct decipkt *pkt)
{
	pkt->hdr.magic = htole16(pkt->hdr.magic);
	pkt->hdr.size = htole16(pkt->hdr.size);
	pkt->hdr.category = htole32(pkt->hdr.category);
	pkt->hdr.priority = htole16(pkt->hdr.priority);
	pkt->hdr.reply = htole16(pkt->hdr.reply);
	pkt->hdr.cid = htole16(pkt->hdr.cid);
	pkt->hdr.seq = htole16(pkt->hdr.seq);
	pkt->hdr.req = htole32(pkt->hdr.req);
}

void pkt_ntoh(struct decipkt *pkt)
{
	pkt->hdr.magic = le16toh(pkt->hdr.magic);
	pkt->hdr.size = le16toh(pkt->hdr.size);
	pkt->hdr.category = le32toh(pkt->hdr.category);
	pkt->hdr.priority = le16toh(pkt->hdr.priority);
	pkt->hdr.reply = le16toh(pkt->hdr.reply);
	pkt->hdr.cid = le16toh(pkt->hdr.cid);
	pkt->hdr.seq = le16toh(pkt->hdr.seq);
	pkt->hdr.req = le32toh(pkt->hdr.req);
}

uint32_t cksum_calculate(struct decipkt *pkt)
{
	uint32_t sum = 0;
	uint32_t *dat = malloc(sizeof(pkt->hdr));
	if (dat == NULL)
		err(1, "cksum_caluclate malloc");
	memcpy(dat, &pkt->hdr, sizeof(pkt->hdr));
	pkt_hton((struct decipkt *)dat);
	for (int i=0; i<7; i++) {
		sum += le32toh(dat[i]);
	}
	free(dat);
	return htole32(sum);
}

void cksum_fix(struct decipkt *pkt)
{
	pkt->hdr.cksum = cksum_calculate(pkt);
}

bool cksum_verify(struct decipkt *pkt)
{
	return cksum_calculate(pkt) == pkt->hdr.cksum;
}

void pkt_print(struct decipkt *pkt)
{
	uint16_t size = pkt->hdr.size;
	printf("header:\n");
	hexdump(&pkt->hdr, sizeof(pkt->hdr));
	if (size > sizeof(pkt->hdr)) {
		printf("body:\n");
		hexdump(pkt->body, size - sizeof(pkt->hdr));
	}
	printf("\n");
}

bool add_queue(struct decipkt *pkt, struct decipkt *queue[], int *num_queue)
{
	// BIG HACK THIS SUCKS
	struct decipkt mypkt;
	memcpy(&mypkt, pkt, sizeof(mypkt));
	cksum_fix(&mypkt);
	pkt_hton(&mypkt);
	//pkt_print(&mypkt);

	ssize_t sz;
	uint8_t *blob = malloc(pkt->hdr.size);
	if (!blob) err(1, "in malloc");
	memcpy(blob, &mypkt, 0x20);
	if (pkt->body)
		memcpy(blob + 0x20, mypkt.body, pkt->hdr.size - 0x20);

	sz = send(sock, blob, pkt->hdr.size, 0);
	if (sz == -1) errnet(1, "couldn't send");

	delete_packet(pkt);
	free(blob);
	return true;
}

bool add_queue_real(struct decipkt *pkt, struct decipkt *queue[], int *num_queue)
{
	int slot;

	if (*num_queue == 99) {
		printf ("pkt buffer overflow\n");
		return false;
	}

	if (*num_queue == 0) {
		queue[0] = pkt;
		(*num_queue)++;
		return true;
	}

	for(slot=0; priority_over (queue[slot], pkt) &&
	      (slot < *num_queue); slot++)
		;

	if (slot < *num_queue) {
		for(int idx = *num_queue-1; idx >=slot; idx--) {
			queue[idx+1] = queue[idx];
		}
		queue[slot] = pkt;
		(*num_queue)++;
	}
	return true;
}

bool add_send_queue(struct decipkt *pkt)
{
	return add_queue(pkt, send_queue, &num_send_queue);
}

bool add_wait_queue(struct decipkt *pkt)
{
	return add_queue(pkt, wait_queue, &num_wait_queue);
}

bool del_queue(struct decipkt *pkt, struct decipkt *queue[], int *num_queue)
{
	if (*num_queue == 0) {
		printf("packet buffer is empty\n");
		return false;
	}

	for (int i=0; i<*num_queue; i++) if (queue[i] == pkt) {
		for (int j=i; j< (*num_queue - 1); j++) {
			queue[j] = queue[j+1];
		}
		return true;
	}
	return false;
}

bool del_send_queue(struct decipkt *pkt)
{
	return del_queue(pkt, send_queue, &num_send_queue);
}

bool del_wait_queue(struct decipkt *pkt)
{
	return del_queue(pkt, wait_queue, &num_wait_queue);
}

bool sdisp(uint32_t opt)
{
	struct decipkt *pkt = new_packet(sizeof(uint32_t));
	*(uint32_t *)pkt->body = htole32(opt);
	pkt->hdr.category = CAT_TTY;
	pkt->hdr.priority = PRI_TTY;
	pkt->hdr.req = REQ_SDISPCTRL;
	return add_send_queue(pkt);
}

bool reset_send(uint32_t opt)
{
	struct decipkt *pkt = new_packet(sizeof(uint32_t)*1);
	uint32_t *body = pkt->body;
	body[0] = htole32(opt);
	//body[1] = htole32(0x44450000);
	//body[2] = htole32(0x544d0001);
	//body[2] = htole32(0x54540002);
	pkt->hdr.category = CAT_T;
	pkt->hdr.priority = PRI_T;
	pkt->hdr.req = REQ_TRESET;
	return add_send_queue(pkt);
}

bool tdbgon_send()
{
	struct decipkt *pkt = new_packet(0);
	pkt->hdr.category = CAT_T;
	pkt->hdr.priority = PRI_T;
	pkt->hdr.req = REQ_TDEBUGGER;
	return add_send_queue(pkt);
}

void dump_packetq(struct decipkt *pkts[], int count)
{
	for (int i=0; i<count; i++) {
		struct decipkt *pkt = pkts[i];
		printf("%3d:priority %04x, category %08x, tag %3d\n",
			i,
			pkt->hdr.priority,
			pkt->hdr.category,
			pkt->hdr.tag
		);
	}
}

bool priority_over(struct decipkt *a, struct decipkt *b)
{
	if (!a || !b) return false;

	uint16_t prio_a = a->hdr.priority;
	uint16_t prio_b = b->hdr.priority;
	uint32_t cat_a  = a->hdr.category;
	uint32_t cat_b  = b->hdr.category;

	if (prio_b < prio_a) return true;
	if (prio_b > prio_a) return false;
	if (cat_b >= cat_a) return false;
	return true;
}
#if 0
void acknak(struct decipkt *pkt)
{
	if (pkt->hdr.priority || pkt->hdr.category) {
		struct decipkt *thingy = new_packet(2);
		uint8_t *body = (uint8_t *)pkt->body;
		body[0] = pkt->hdr.tag;
		body[1] = 0;
		thingy->hdr.req = REQ_ZACKNAK;
		add_send_queue(thingy);
	}
	uint8_t acktag;
	uint8_t ackcode;
	if (pkt->hdr.req != REQ_ZACKNAK) {
		if (pkt->hdr.acktag != 0) {
			ackcode = pkt->hdr.ackcode;
			acktag = pkt->hdr.acktag;
		}
	} else {
		uint8_t *body = (uint8_t *)(pkt->body);
		acktag = body[0];
		ackcode = body[1];
	}
	// TODO
}
#endif
bool comstat_send()
{
	struct decipkt *pkt = new_packet(0);
	pkt->hdr.req = REQ_ZCOMSTAT;
	return add_send_queue(pkt);
}

bool retry_send()
{
	struct decipkt *pkt = new_packet(0);
	pkt->hdr.req = REQ_ZALLRETRY;
	return add_send_queue(pkt);
}

bool hwconf_send()
{
	struct decipkt *pkt = new_packet(0);
	pkt->hdr.req = REQ_ZHWCONFIG;
	return add_send_queue(pkt);
}

bool getinfo_send()
{
	struct decipkt *pkt = new_packet(0);
	pkt->hdr.req = REQ_ZGETINFO;
	return add_send_queue(pkt);
}

bool myacknak(uint8_t ack, uint8_t nak)
{
	struct decipkt *pkt = new_packet(2);
	uint8_t *buf = (uint8_t *)pkt->body;
	buf[0] = ack;
	buf[1] = nak;
	pkt->hdr.req = REQ_ZACKNAK;
	return add_send_queue(pkt);
}

bool tmode_send(uint32_t mode)
{
	struct decipkt *pkt = new_packet(4);
	uint32_t *buf = (uint32_t *)pkt->body;
	buf[0] = htole32(mode);
	pkt->hdr.req = REQ_TMODE;
	pkt->hdr.category = CAT_T;
	pkt->hdr.priority = PRI_T;
	pkt->hdr.tag = 0;
	return add_send_queue(pkt);
}

bool isetbootname_send(const char *name)
{
	struct decipkt *pkt = new_packet(sizeof(struct isetbootname_body_s));
	struct isetbootname_body_s *body = (struct isetbootname_body_s *)pkt->body;
	strncpy(body->name, name, sizeof(body->name) - 1);
	pkt->hdr.req = REQ_ISETBOOTNAME;
	pkt->hdr.category = CAT_IPL;
	pkt->hdr.priority = PRI_IPL;
	pkt->hdr.tag = 0x77;
	return add_send_queue(pkt);
}

bool idownload_send(uint32_t addr, uint32_t len, uint8_t *data)
{
	if (!data) return false;
	struct decipkt *pkt = new_packet(sizeof(struct idownload_body_s) + len);
	struct idownload_body_s *body = (struct idownload_body_s *)pkt->body;
	body->addr = htole32(addr);
	body->len = htole32(len);
	memcpy(body->data, data, len);

	pkt->hdr.req = REQ_IDOWNLOAD;
	pkt->hdr.category = CAT_IPL;
	pkt->hdr.priority = PRI_IPL;
	pkt->hdr.tag = 0x88;
	return add_send_queue(pkt);
}

bool irun_send_exe(struct psxexe_s *exe)
{
	if (!exe) return false;
	struct decipkt *pkt = new_packet(sizeof(struct irun_body_s) + 13);
	struct irun_body_s *body = (struct irun_body_s *)pkt->body;
	body->pc = exe->pc;
	body->gp = exe->gp;
	body->vma = exe->vma;
	body->size = exe->size;
	body->bss_addr = exe->bss_addr;
	body->bss_size = exe->bss_size;
	body->sp_fp_base = exe->sp_fp_base;
	body->sp_fp_offset = exe->sp_fp_offset;
	body->flag = htole32(1);
	body->namelen = htole32(strlen("whatever.exe") + 1);
	strcpy((char *)body->name, "whatever.exe");

	pkt->hdr.req = REQ_IRUN;
	pkt->hdr.category = CAT_IPL;
	pkt->hdr.priority = PRI_IPL;
	pkt->hdr.tag = 0x99;
	return add_send_queue(pkt);
}

bool irun_send(uint32_t pc, uint32_t sp)
{
	struct decipkt *pkt = new_packet(sizeof(struct irun_body_s) + 13);
	struct irun_body_s *body = (struct irun_body_s *)pkt->body;
	body->pc = htole32(pc);
	body->sp_fp_base = htole32(sp);
	body->sp_fp_offset = htole32(0);
	body->flag = htole32(1);
	body->namelen = htole32(strlen("whatever.exe") + 1);
	strcpy((char *)body->name, "whatever.exe");

	pkt->hdr.req = REQ_IRUN;
	pkt->hdr.category = CAT_IPL;
	pkt->hdr.priority = PRI_IPL;
	pkt->hdr.tag = 0x99;
	return add_send_queue(pkt);
}

bool dmemread_send(void *buf, uint32_t n, uint32_t src)
{
	struct decipkt *pkt = new_packet(sizeof(struct dmemread_body_s));
	struct dmemread_body_s *body = (struct dmemread_body_s *)pkt->body;
	body->zero = htole32(0);
	body->addr = htole32(src);
	body->n = htole32(n);

	pkt->hdr.req = REQ_DMEMREAD;
	pkt->hdr.category = CAT_DBG;
	pkt->hdr.priority = PRI_DBG;
	pkt->hdr.tag = 0x66;
	pkt->hdr.reply = 1;
	return add_send_queue(pkt);
}

bool dgetreg_send(uint32_t cpumask, uint32_t gpumask)
{
	struct decipkt *pkt = new_packet(sizeof(struct dgetreg_body_s));
	struct dgetreg_body_s *body = (struct dgetreg_body_s *)pkt->body;

	body->mask[0] = 0;
	body->mask[1] = 3;
	body->mask[2] = -1;
	body->mask[3] = le32toh(0x7000);

	pkt->hdr.req = REQ_DGETREG;
	pkt->hdr.category = 0x1e;
	pkt->hdr.priority = 0x1f;
	pkt->hdr.tag = 0x68;
	pkt->hdr.reply = 1;
	return add_send_queue(pkt);
}

bool tpalntsc_send(uint32_t ispal)
{
	struct decipkt *pkt = new_packet(sizeof(struct tpalntsc_body_s));
	struct tpalntsc_body_s *body = (struct tpalntsc_body_s *)pkt->body;
	body->ispal = htole32(ispal);

	pkt->hdr.req = REQ_TCOLORSYSTEM;
	pkt->hdr.category = CAT_IPL;
	pkt->hdr.priority = PRI_IPL;
	pkt->hdr.tag = 0x78;
	return add_send_queue(pkt);
}

bool dcontinue_send(uint32_t param)
{
	struct decipkt *pkt = new_packet(sizeof(struct dcontinue_body_s));
	struct dcontinue_body_s *body = (struct dcontinue_body_s *)pkt->body;
	body->param = htole32(param);

	pkt->hdr.req = REQ_DCONTINUE;
	pkt->hdr.category = 0x1e;
	pkt->hdr.priority = 0x1f;
	pkt->hdr.tag = 0x75;
	return add_send_queue(pkt);
}

