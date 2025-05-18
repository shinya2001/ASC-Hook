#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <dis-asm.h>
#include <sched.h>
#include <dlfcn.h>
#include <elf.h>
#include <inttypes.h>
#include <signal.h>
#include <unistd.h>
#include <ucontext.h>
#include <setjmp.h>
#include "gotcha.h"

#define PAGE_SIZE 4096
#define BARRIER1 209715200LL
// This reserves at least 200MB of virtual memory for the heap and stack

#define BARRIER2 65536
// This defines the minimum amount of virtual memory reserved for the first-level trampoline
#define BARRIER3 294912
// This defines the minimum amount of virtual memory reserved for the second-level trampoline

#define ALIGN_TO_PAGE(addr) ((uintptr_t)(addr) & ~(PAGE_SIZE - 1))

#define ADRP_RANGE 0x100000000

struct info_ku fill_Ku[MAX_KU_NUM];int full_ku_num;
uint64_t haved_page[100000],haved_page2[100000],num_haved_page,num_haved_page2,stack_addr,heap_addr;
// `haved_pages` stores the virtual memory pages that have already been used; it contains the starting addresses of those pages.
// `have_page2` holds the pages that were added later by our code.

void getfullku(char* buf){
	int i = 0;
	char addr[65] = { 0 };
	char *c = strtok(buf, " ");
	while (c != NULL) {
		switch (i) {
			case 0:
			strncpy(addr, c, sizeof(addr) - 1);// The first extracted segment is a virtual address range containing a dash, such as 0x22222-0x333333
			break;
			case 1:
			{
				int mem_prot = 0;// Indicates the permissions of this segment (VMA)
				{
					size_t j;
					for (j = 0; j < strlen(c); j++) {
						if (c[j] == 'r')
							mem_prot |= PROT_READ;
						if (c[j] == 'w')
							mem_prot |= PROT_WRITE;
						if (c[j] == 'x')
							mem_prot |= PROT_EXEC;
					}
				}
			/* rewrite code if the memory is executable */
						size_t k;
						for (k = 0; k < strlen(addr); k++) {// Replace the dash (`-`) in the middle with `'\0'`
							if (addr[k] == '-') {
								addr[k] = '\0';
								break;
							}
						}
					{
						int64_t from, to;
						from = strtol(&addr[0], NULL, 16);// Used to convert a string into a number; see below for a detailed explanation
                        
						if (from == 0) {
						/*
					     * this is trampoline code.
                        * so skip it.
						 */
						    break;
						}
						to = strtol(&addr[k + 1], NULL, 16);// This retrieves the end address of the segment
						++full_ku_num;
						fill_Ku[full_ku_num].bs_addr = (int*)from;
						fill_Ku[full_ku_num].ex_bs_addr = (int*)from;
						fill_Ku[full_ku_num].ex_size = to - from;
						fill_Ku[full_ku_num].ex_mem_prot = mem_prot;
					}
			}
			break;

			case 5:// File path
			{
				char* file_name = NULL;
				file_name = getFileName(c);
				strcpy(fill_Ku[full_ku_num].ku_name,file_name);
			}
		    break;
		}
		if(i == 5) break;
		c = strtok(NULL, " ");
		i++;
	}
	
}

void adrp_init(){
	
	for(int i = 1; i <= full_ku_num; i++){
		uint64_t align_page = ALIGN_TO_PAGE(fill_Ku[i].bs_addr);
		uint64_t page_to = (uint64_t)fill_Ku[i].bs_addr + fill_Ku[i].ex_size;
		while(align_page <= page_to){// Add all used virtual addresses from this line to `haved_page`.  
// This helps identify occupied regions, so our trampolines are only placed in unused memory.

			haved_page[++num_haved_page] = align_page;
			align_page += PAGE_SIZE;
		}
        char *result = strstr(fill_Ku[i].ku_name, "stack");
		if (result != NULL) {
			stack_addr = (uint64_t)fill_Ku[i].bs_addr;
    	}
		result = strstr(fill_Ku[i].ku_name, "heap");
    	if (result != NULL) {
			heap_addr = (uint64_t)(fill_Ku[i].bs_addr + fill_Ku[i].ex_size);
    	}
	}
	qsort(haved_page + 1, num_haved_page, sizeof(uint64_t), compare);
	
}

bool contains(uint64_t* begin, uint64_t* end, uint64_t value) {
    uint64_t* pos = lower_bound(begin, end, value);
    return (pos != end && *pos == value);
}

bool judge_have(uint64_t addr){
	if(contains(haved_page + 1, haved_page + 1 + num_haved_page, addr)){
		return false;
	}
	if(contains(haved_page2 + 1, haved_page2 + 1 + num_haved_page2, addr)){
		return false;
	}
	if((addr >= BASE_FUNC_COMMON_F) && (addr <= BASE_FUNC_COMMON_F + BARRIER2)){// Reserved for our own first-level trampoline
		return false;
	}
	if(((uint64_t)addr >= (uint64_t)PERSONAL_FUNC_BASE) && ((uint64_t)addr <= (uint64_t)(PERSONAL_FUNC_BASE + BARRIER3))){// Reserved for our own second-level trampoline
		return false;
	}
	if((addr >= stack_addr - BARRIER1) && (addr <= stack_addr)){// Reserved for the stack
		return false;
	}
	if((addr >= heap_addr) && (addr <= heap_addr + BARRIER1)){// Reserved for the heap
		return false;
	}
	return true;
}

void adrp_alloc_adress(int id){
	uint64_t SVC = (uint64_t)mod_p[id].insSVC;
	uint64_t l = (SVC - ADRP_RANGE + PAGE_SIZE),r = (SVC + ADRP_RANGE - PAGE_SIZE);
	l = ALIGN_TO_PAGE(l) ,r = ALIGN_TO_PAGE(r);
	if(l < PAGE_SIZE) l = PAGE_SIZE;
	while(l<=r){
		if(judge_have(l)){
			mod_p[id].com_aim_addr = l;
			haved_page2[++num_haved_page2] = l;
			qsort(haved_page2 + 1, num_haved_page2, sizeof(uint64_t), compare);	
			 void *mem = mmap((void *)mod_p[id].com_aim_addr , 4096,
				PROT_READ | PROT_WRITE | PROT_EXEC,
				MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
				-1, 0);
			if (mem == MAP_FAILED) {
				fprintf(stderr, "map3 failed\n");
		  		fprintf(stderr, "NOTE: /proc/sys/vm/mmap_min_addr should be set 0\n");
		  		exit(1);
	  		}
			return;
		}
		l+=PAGE_SIZE;
	}
	return;
}

uint32_t get_adrp(uint64_t pc, uint64_t target) {
    // Ensure both pc and target are 4KB aligned
    if ((pc & 0xFFF) != 0 || (target & 0xFFF) != 0) {
        puts("please  Ensure both pc and target are 4KB aligned");
		exit(0);
    }

    // Calculate the difference and divide by 4096 (right shift 12 bits)
    int64_t diff = (target - pc) >> 12;

    // Split the difference into immhi and immlo
    uint32_t immhi = (diff >> 2) & 0x7FFFF;  // high 19 bits
    uint32_t immlo = diff & 0x3;             // low 2 bits

    // Construct the instruction
    uint32_t instruction = (immlo << 29) | (immhi << 5) | 0x90000008;

    return instruction;
}


void adrp_exchange(int id){
	uint64_t i = (uint64_t)mod_p[id].insSVC,j = mod_p[id].com_aim_addr;
	uint32_t ans = get_adrp(ALIGN_TO_PAGE(i),ALIGN_TO_PAGE(j));
	uint8_t* addr_per = (uint8_t*)(&ans);
	for(int k = 0;k < 4; k++){
        mod_p[id].machine_codes[k] = addr_per[k];
    }
	uint32_t br_x8 = 0xD61F0100;
    uint8_t* br_x8_bytes = (uint8_t*)&br_x8;
    for(int k = 0; k < 4; k++){
        mod_p[id].machine_codes[4 + k] = br_x8_bytes[k];
    }
}