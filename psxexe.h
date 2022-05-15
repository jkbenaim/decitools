#ifndef _PSXEXE_H_
#define _PSXEXE_H_

#include <stdint.h>

struct psxexe_s {
	uint8_t magic[16];	// "PS-X EXE\0\0\0\0\0\0\0"
	uint32_t pc;
	uint32_t gp;
	uint32_t vma;
	uint32_t size;		// must be multiple of 2048
	uint32_t _unused20;
	uint32_t _unused24;
	uint32_t bss_addr;
	uint32_t bss_size;
	uint32_t sp_fp_base;
	uint32_t sp_fp_offset;
	uint32_t _unused38;
	uint32_t _unused3c;
	uint32_t _unused40;
	uint8_t sce_text[0x7b4];
} __attribute__((packed));

#endif
