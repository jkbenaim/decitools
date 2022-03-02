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
#define REQ_DRUN		(0)
#define REQ_DCONTINUE		(0)
#define REQ_DBREAK		(0)
#define REQ_DGETREG		(0)
#define REQ_DPUTREG		(0)
#define REQ_DMEMWRITE		(0)
#define REQ_DMEMREAD		(0)
#define REQ_DMEMFILL		(0)
#define REQ_DHALT		(0)
#define REQ_D_IDK		(0x44810000)
#define REQ_IDOWNLOAD		(0x49010100)
#define REQ_IRUN		(0x49020100)
#define REQ_I_03		(0x49030100)
#define REQ_SSEND		(0x53010100)
#define REQ_SDISPCTRL		(0x53810000)
#define REQ_TRESET		(0x54010000)
#define REQ_T_02		(0x54020201)
#define REQ_T_03		(0x54030201)
#define REQ_T_04		(0x54040000)
#define REQ_T_06		(0x54060000)
#define REQ_T_07		(0x54070100)
#define REQ_T_0A		(0x540A0000)
#define REQ_FFFF0201		(0xffff0201)

/* categories */
#define CAT_TPKT	(0x0000000A)
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

struct idownload_body {
	uint32_t idk;
	uint32_t addr;
	uint32_t len;
	uint8_t data[]; // note: padded with zeros up to multiple of 4 bytes
} __attribute__((packed));

struct decipkt *new_packet(size_t body_size);
void delete_packet(struct decipkt *pkt);
void pkt_hton(struct decipkt *pkt);
void pkt_ntoh(struct decipkt *pkt);
bool cksum_verify(struct decipkt *pkt);
void cksum_fix(struct decipkt *pkt);
bool add_send_queue(struct decipkt *pkt);
bool add_wait_queue(struct decipkt *pkt);
bool del_send_queue(struct decipkt *pkt);
bool del_wait_queue(struct decipkt *pkt);
bool sdisp(uint32_t opt);
bool reset_send(uint32_t opt);
void dump_packetq(struct decipkt *pkts[], int count);
bool priority_over(struct decipkt *a, struct decipkt *b);
void acknak(struct decipkt *pkt);
bool comstat_send();
bool retry_send();
bool hwconf_send();
bool myacknak(uint8_t ack, uint8_t nak);
#endif
