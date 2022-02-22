#ifndef _DECI_H_
#define _DECI_H_

#include <stdbool.h>
#include <stdint.h>
#include <endian.h>

#define DECI_MAGIC	(0xa14c)

/* types for pkt.req */
#define REQ_ZACKNAK		(0x01010100)
#define REQ_ZPANICMSG		(0x01020100)
#define REQ_ZHWCONFIG		(0x01030100)
#define REQ_ZCOMSTAT		(0x01040100)
#define REQ_ZALLRETRY		(0x01050100)
#define REQ_SSEND		(0x53010100)
#define REQ_SDISPCTRL		(0x53810000)
#define REQ_TRESET		(0x54010000)
#define REQ_IDOWNLOAD		(0x49010100)
#define REQ_IRUN		(0x49020100)

/* categories */
#define CAT_A		(0x0000000A)
#define CAT_IPL 	(0x00000028)
#define CAT_TTY		(0x54545920)
#define CAT_FILE	(0x46494C45)

struct decihdr {
	uint16_t magic;
	uint16_t size;
	uint32_t category;
	uint16_t priority;
	uint16_t rep;
	uint8_t tag;
	uint8_t acktag;
	uint8_t ackcode;
	uint8_t crsv[5];
	uint16_t cid;
	uint16_t seq;
	uint32_t req;
	uint32_t cksum;
} __attribute__((packed));

struct decipkt {
	struct decihdr hdr;
	void *body;
	void *buf_b;
};

struct decipkt *new_packet();
void delete_packet(struct decipkt *pkt);
void pkt_hton(struct decipkt *pkt);
void pkt_ntoh(struct decipkt *pkt);
bool cksum_verify(struct decipkt *pkt);
void cksum_fix(struct decipkt *pkt);
bool add_send_queue(struct decipkt *pkt);
bool add_wait_queue(struct decipkt *pkt);
bool del_send_queue(struct decipkt *pkt);
bool del_wait_queue(struct decipkt *pkt);
bool sdisp();
bool reset_send();
void dump_packetq(struct decipkt *pkts[], int count);
bool priority_over(struct decipkt *a, struct decipkt *b);
void acknak(struct decipkt *pkt);
bool comstat_send();
bool retry_send();
bool hwconf_send();
#endif
