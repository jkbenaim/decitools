#include <endian.h>
#include <err.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "deci.h"
#include "hexdump.h"

struct decipkt *send_queue[100];
struct decipkt *wait_queue[100];
int num_send_queue;
int num_wait_queue;
int packetsize;
int needhwconf;
int timeoutval;

struct decipkt *new_packet()
{
	struct decipkt *pkt = malloc(sizeof(struct decipkt));
	if (pkt == NULL) err(1, "new_packet malloc");
	memset(pkt, 0, sizeof(struct decipkt));
	return pkt;
}

void delete_packet(struct decipkt *pkt)
{
	if (pkt)
		free(pkt->body);
	free(pkt);
}

uint32_t cksum_calculate(struct decipkt *pkt)
{
	uint32_t sum = 0;
	uint32_t *dat = malloc(sizeof(pkt->hdr));
	if (dat == NULL)
		err(1, "cksum_caluclate malloc");
	memcpy(dat, &pkt->hdr, sizeof(pkt->hdr));
	for (int i=0; i<7; i++) {
		sum += le32toh(dat[i]);
	}
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
	uint16_t size = le16toh(pkt->hdr.size);
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

bool sdisp()
{
	struct decipkt *pkt = new_packet();
	uint32_t *body = malloc(sizeof(uint32_t));
	pkt->body = body;
	*body = 0;
	pkt->hdr.magic = DECI_MAGIC;
	pkt->hdr.size = htole16(0x24);
	pkt->hdr.category = CAT_TTY;
	pkt->hdr.priority = htole16(0x3c);
	pkt->hdr.req = REQ_SDISPCTRL;
	return add_send_queue(pkt);
}

bool reset_send()
{
	struct decipkt *pkt = new_packet();
	uint32_t *body = malloc(sizeof(uint32_t));
	pkt->body = body;
	*body = htole32(1);
	pkt->hdr.magic = DECI_MAGIC;
	pkt->hdr.size = htole16(0x24);
	pkt->hdr.category = CAT_A;
	pkt->hdr.priority = htole16(0xa);
	pkt->hdr.req = REQ_TRESET;
	return add_send_queue(pkt);
}

void dump_packetq(struct decipkt *pkts[], int count)
{
	for (int i=0; i<count; i++) {
		struct decipkt *pkt = pkts[i];
		printf("%3d:priority %04x, category %08x, tag %3d\n",
			i,
			le16toh(pkt->hdr.priority),
			le32toh(pkt->hdr.category),
			pkt->hdr.tag
		);
	}
}

bool priority_over(struct decipkt *a, struct decipkt *b)
{
	if (!a || !b) return false;

	uint16_t prio_a = le16toh(a->hdr.priority);
	uint16_t prio_b = le16toh(b->hdr.priority);
	uint32_t cat_a  = le32toh(a->hdr.category);
	uint32_t cat_b  = le32toh(b->hdr.category);

	if (prio_b < prio_a) return true;
	if (prio_b > prio_a) return false;
	if (cat_b >= cat_a) return false;
	return true;
}

void acknak(struct decipkt *pkt)
{
	if (pkt->hdr.priority || pkt->hdr.category) {
		struct decipkt *thingy = new_packet();
		uint8_t *body = malloc(2);
		body[0] = pkt->hdr.tag;
		body[1] = 0;
		thingy->body = body;
		thingy->hdr.magic = DECI_MAGIC;
		thingy->hdr.size = le16toh(0x22);
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

}

bool comstat_send()
{
	struct decipkt *pkt = new_packet();
	pkt->hdr.magic = DECI_MAGIC;
	pkt->hdr.size = htole16(0x20);
	pkt->hdr.req = REQ_ZCOMSTAT;
	return add_send_queue(pkt);
}

bool retry_send()
{
	struct decipkt *pkt = new_packet();
	pkt->hdr.magic = DECI_MAGIC;
	pkt->hdr.size = htole16(0x20);
	pkt->hdr.req = REQ_ZALLRETRY;
	return add_send_queue(pkt);
}

bool hwconf_send()
{
	struct decipkt *pkt = new_packet();
	pkt->hdr.magic = DECI_MAGIC;
	pkt->hdr.size = htole16(0x20);
	pkt->hdr.req = REQ_ZHWCONFIG;
	return add_send_queue(pkt);
}