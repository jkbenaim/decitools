#ifndef _DECI_H_
#define _DECI_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "endian.h"

#include "psxexe.h"

#define DECI_MAGIC	(0xa14c)

/* types for pkt.req */
/* category, priority, packet size incl 20h-byte header */
/* 0, 0, 22h */
#define REQ_ZACKNAK		(0x01010100)
#define REQ_ZPANICMSG		(0x01020100)
#define REQ_ZHWCONFIG		(0x01030100)
#define REQ_ZCOMSTAT		(0x01040100)
#define REQ_ZALLRETRY		(0x01050100)
#define REQ_ZGETINFO		(0x01060100)
#define REQ_Z_07		(0x01070100)
#define REQ_CSEND		(0x43010100)
#define REQ_CSENDACK		(0x43020101)
#define REQ_CRCVREQ		(0x43030201)
#define REQ_DRUN		(0x44010100)
/* CAT_DBG, PRI_DBG, 24h */
#define REQ_DCONTINUE		(0x44020000)
/* CAT_DBG, PRI_DBG, 20h */
#define REQ_DBREAK		(0x44030000)
/* CAT_DBG, PRI_DBG, 48h */
#define REQ_DGETREG		(0x44040201)
/* CAT_DBG, PRI_DBG, 48h + var */
#define REQ_DPUTREG		(0x44050100)
/* CAT_DBG, PRI_DBG, 2Ch + var */
#define REQ_DMEMWRITE		(0x44060100)
/* CAT_DBG, PRI_DBG, ?? */
#define REQ_D_0601		(0x44060101)
#define REQ_DMEMFILL		(0x44070100)
/* CAT_DBG, PRI_DBG, 2Ch or 34h? */
#define REQ_DMEMREAD		(0x44080201)
#define REQ_DHALT		(0x44810000)
#define REQ_EADDRESS		(0x45010201)
/* CAT_FILE, PRI_FILE, 28h */
#define REQ_FOPEN		(0x46010001)
/* CAT_FILE, PRI_FILE, 24h */
#define REQ_FCLOSE		(0x46020001)
/* CAT_FILE, PRI_FILE, ?? */
#define REQ_FREAD		(0x46030201)
#define REQ_FWRITE		(0x46040101)
/* CAT_FILE, PRI_FILE, 28h */
#define REQ_FSEEK		(0x46050001)
#define REQ_IDOWNLOAD		(0x49010100)
#define REQ_IRUN		(0x49020100)
#define REQ_ISETBOOTNAME	(0x49030100)
#define REQ_NRESET		(0x4E010000)
#define REQ_NHWCONFIG		(0x4E020000)
#define REQ_NCOMSTAT		(0x4E030000)
#define REQ_SSEND		(0x53010100)
#define REQ_SDISPCTRL		(0x53810000)
#define REQ_TRESET		(0x54010000)
#define REQ_TGETHWCONFIG	(0x54020201)
#define REQ_TGETCOMSTAT		(0x54030201)
/* CAT_T, PRI_T, 24h */
#define REQ_TMODE		(0x54040000)
#define REQ_TDOWNLOAD		(0x54040100)
/* CAT_T, PRI_T, 24h */
#define REQ_TCOLORSYSTEM	(0x54050000)
#define REQ_TRUN		(0x54050100)
/* CAT_T, PRI_T, 20h */
#define REQ_TDEBUGGER		(0x54060000)
#define REQ_TSETID		(0x54070100)
/* sent by metrowerks' PSComUtil, but it doesn't know the name of it... */
/* CAT_T, PRI_T, 70h */
#define REQ_T_08		(0x54080101)
/* CAT_T, PRI_T, 24h */
#define REQ_TCDROMEMU		(0x540A0000)
#define REQ_T_10		(0x54100101)
#define REQ_TEXIT		(0x547F0000)
#define REQ_FFFF0201		(0xffff0201)

/* categories */
#define CAT_9		(0x00000009)
#define CAT_T		(0x0000000A)
#define CAT_DBG		(0x0000001E)
#define CAT_IPL 	(0x00000028)
#define CAT_FILE	(0x46494C45)
#define CAT_TTY		(0x54545920)

/* priorities */
#define PRI_T		(0x0000000A)
#define PRI_DBG		(0x0000001F)
#define PRI_IPL		(0x00000028)
#define PRI_FILE	(0x00000032)
#define PRI_TTY		(0x0000003C)

struct decihdr {
	uint16_t magic;
	uint16_t size;
	uint32_t category;
	uint16_t priority;
	uint16_t reply;
	uint8_t tag;
	uint8_t acktag;
	uint8_t ackcode;
	uint8_t pad;
	uint32_t crsv;
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

struct idownload_body_s {
	uint32_t flags;
	uint32_t addr;
	uint32_t len;
	uint8_t data[]; // note: padded with zeros up to multiple of 4 bytes
} __attribute__((packed));

struct irun_body_s {
	uint32_t pc;
	uint32_t gp;
	uint32_t vma;
	uint32_t size;
	uint32_t _unused10;
	uint32_t _unused14;
	uint32_t bss_addr;
	uint32_t bss_size;
	uint32_t sp_fp_base;
	uint32_t sp_fp_offset;
	uint32_t _unused28;
	uint32_t _unused2c;
	uint32_t _unused30;
	uint32_t _unused34;
	uint32_t _unused3c;
	uint32_t flag;		// always 1?
	uint32_t namelen;	// including null terminator
	uint32_t _unused44;
	unsigned char name[];
} __attribute__((packed));

struct isetbootname_body_s {
	char name[64];
} __attribute__((packed));

struct zgetinfo_body_s {
	// total size with header should be 0x94
	uint32_t deciflags;
	uint32_t field_4;
	uint32_t field_8;
	uint32_t last_seq;
	uint32_t field_10;
	uint32_t crsv_1;
	uint32_t field_18;
	uint32_t innerqueue;
	uint32_t field_20;
	uint32_t field_24;
	uint32_t field_28;
	uint32_t field_2c[18];
} __attribute__((packed));

struct fopen_body_s {
	uint32_t idk;
	uint32_t namesize;
	uint8_t name[];
} __attribute__((packed));

struct dmemread_body_s {
	uint32_t zero;
	uint32_t addr;
	uint32_t idk8;
	uint32_t n;
	uint8_t data[];
} __attribute__((packed));

struct dmemwrite_body_s {
	uint32_t flags;	// must be nonzero
	uint32_t dest;
	uint32_t nbytes;
	uint32_t blocksize;
	uint8_t data[];
} __attribute__((packed));

struct d_08_01_body_s {
	uint32_t a;	// must be nonzero
	uint32_t b;
	uint32_t c;
} __attribute__((packed));

struct comstat {
	uint32_t cat;
	uint32_t pri;
	uint32_t opt;
} __attribute__((packed));

struct hwconfig {
	uint32_t numfields;
	union {
		struct {
			uint32_t romdate;
			uint32_t romtype;
			uint32_t romname_len;
			uint32_t cpu_prid;
			uint32_t board_id;
			uint32_t ram_size;
			uint32_t gpu_type;
			uint32_t vram_size;
			uint32_t spu_type;
			uint32_t spu_ram_size;
			uint32_t debugger_type;
			uint32_t host_if_type;
			uint32_t pad_present;
			uint32_t memcard_present;
			uint32_t cdrom_present;
			uint32_t host_if_bufsize;
		};
		uint32_t fields[16];
	};
	char romname[];
} __attribute__((packed));

struct dgetreg_body_s {
	uint32_t mask[10];
} __attribute__((packed));

struct tpalntsc_body_s {
	uint32_t ispal;
} __attribute__((packed));

struct dcontinue_body_s {
	uint32_t param;
} __attribute__((packed));

struct dhalt_body_s {
	uint32_t haltcode;
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
bool getinfo_send();
bool memread_send();
bool myacknak(uint8_t ack, uint8_t nak);
bool isetbootname_send(const char *name);
bool idownload_send(uint32_t addr, uint32_t len, uint8_t *data);
bool irun_send_exe(struct psxexe_s *exe);
bool irun_send(uint32_t pc, uint32_t sp);
bool tmode_send(uint32_t mode);
bool dmemread_send(void *buf, uint32_t n, uint32_t src);
bool tdbgon_send();
bool dgetreg_send(uint32_t cpumask, uint32_t gpumask);
bool tpalntsc_send(uint32_t ispal);
bool dcontinue_send(uint32_t param);
#endif
