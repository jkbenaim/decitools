#ifndef _PSXEXE_H_
#define _PSXEXE_H_

#include <stdint.h>

struct psxexe_s {
	uint8_t magic[8];	// "PS-X EXE" no null byte at end
	uint32_t _unused08;
	uint32_t _unused0c;
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
	uint32_t _unused38;	// overwritten, used as old sp by bootloader
	uint32_t _unused3c;	// overwritten, used as old fp by bootloader
	uint32_t _unused40;	// overwritten, used as old gp by bootloader
	uint8_t sce_text[0x7bc];
} __attribute__((packed));

#endif
