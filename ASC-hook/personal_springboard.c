#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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
#include <keystone/keystone.h>
#include <inttypes.h> 
#define MAX_KU_NUM 500
#define MAXN_MOD_POINT 5000
#include "gotcha.h"
#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))

static ks_engine *ks;

void generate_AimAddress(){
    unsigned long long now_mod_addr = BASE_FUNC_COMMON_F;
    for(int i = 1;i <= num_Mod_point;i++){// This is  generating the target addresses for the first-level trampolines
        if(mod_p[i].signal_handle) continue;
        if( i >= BASELINE){// Our BASELINE is set to 3800, but it can actually go up to 3840
            // In other words, if it exceeds 3800, the ADRP-based replacement method must be used
            adrp_alloc_adress(i);
            continue;
        }
        mod_p[i].com_aim_addr = now_mod_addr;// This initializes the target address of the first-level trampoline, starting from 4096 and increasing incrementally
        now_mod_addr +=SIZE_FUNC_COMMON_F; // The first-level trampoline consists of 4 instructions, so 16 bytes are allocated each time
    }
    unsigned long long sz = (now_mod_addr - BASE_FUNC_COMMON_F + PAGE_SIZE - 1);
    unsigned long long szz = sz / 4096;
    unsigned long long aligned_sz = szz * 4096;
    if(aligned_sz < 4096) aligned_sz = 4096;
    void *mem;
	// Allocate virtual addresses for all first-level trampolines here
	  mem = mmap((void *)BASE_FUNC_COMMON_F , aligned_sz,
			PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
			-1, 0);
	  if (mem == MAP_FAILED) {
		  fprintf(stderr, "map failed\n");
		  fprintf(stderr, "NOTE: /proc/sys/vm/mmap_min_addr should be set 0\n");
		  exit(1);
	  }


 
    // Below is the virtual memory allocation and jump address assignment for the second-level trampolines
    unsigned long long now_per_addr = (unsigned long long)PERSONAL_FUNC_BASE;
    for(int i = 1;i <= num_Mod_point;i++){
        if(mod_p[i].signal_handle) continue;// Those handled by signals do not need a personalized trampoline
         mod_p[i].per_aim_addr = now_per_addr;
         now_per_addr += SIZE_FUNC_PER_PER;// SIZE_FUNC_PER_PER is the number of bytes required for our second-level trampoline

    }
    sz = (now_per_addr - (unsigned long long)PERSONAL_FUNC_BASE + PAGE_SIZE - 1)/4096;
    aligned_sz = sz * 4096;
    if(aligned_sz < 4096) aligned_sz = 4096;
	/* allocate memory at virtual address 0 */
	  mem = mmap(PERSONAL_FUNC_BASE , aligned_sz,
			PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
			-1, 0);// Allocate virtual address for the second-level trampoline
	  if (mem == MAP_FAILED) {
		  fprintf(stderr, "map failed\n");
		  fprintf(stderr, "NOTE: /proc/sys/vm/mmap_min_addr should be set 0\n");
		  exit(1);
	  }
    
}

int compile_asm_string(const char* asm_string,uint8_t* uint8_array, size_t uint8_array_size) {
    // This is an API wrote using Keystone. The first parameter is the assembly string to be disassembled,  
    // the second is a uint8_t array to receive the binary code, and the third is the size of that array to prevent overflow.

    // Compile the assembly string
    size_t count;
    unsigned char *encode;
    size_t size;
    if (ks_asm(ks, asm_string, 0, &encode, &size, &count) != KS_ERR_OK) {
        printf("ERROR: ks_asm() failed & count = %lu, error = %u\n",
               count, ks_errno(ks));
        ks_close(ks);
        return -1;
    } else {
        for (size_t i = 0; i < size; i++) {
            if (i < uint8_array_size) {
                uint8_array[i] = encode[i];
            }
        }
    }
    ks_free(encode);
    return 0;
}

int keystone_init(){
    // Initialize Keystone for ARM64 architecture in 64-bit mode 
    ks_err err;
    err = ks_open(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, &ks);
    if (err != KS_ERR_OK) {
        printf("ERROR: failed on ks_open(), quit\n");
        return -1;
    }
    return 0;
}

void keystone_free(){
    ks_close(ks);
}

void generate_string_Springboard(uint64_t aim_addr,char* s){
    uint64_t aim1 = aim_addr&0xffff,aim2 = ((aim_addr&0xffff0000)>>16),aim3 = ((aim_addr&0xffff00000000)>>32);
    sprintf(s,"movz x8, 0x%04llX, LSL 32;movk x8, 0x%04llX, LSL 16;movk x8, 0x%04llX;BR x8;",(long long unsigned int)aim3,(long long unsigned int)aim2,(long long unsigned int)aim1);
}



void generate_per_string_Springboard(uint64_t svc_addr,char* s){
    uint64_t ret_addr = svc_addr + 4;
    uint64_t aim_addr = (uint64_t)asm_syscall_hook;
    uint64_t aim1 = aim_addr&0xffff,aim2 = ((aim_addr&0xffff0000)>>16),aim3 = ((aim_addr&0xffff00000000)>>32);
    uint64_t ret1 = ret_addr&0xffff,ret2 = ((ret_addr&0xffff0000)>>16),ret3 = ((ret_addr&0xffff00000000)>>32);
    sprintf(s,"sub sp, sp, #16;str x8, [sp, #8];movz x8, 0x%04llX, LSL 32;movk x8, 0x%04llX, LSL 16;movk x8, 0x%04llX;str x8, [sp];movz x8, 0x%04llX, LSL 32;movk x8, 0x%04llX, LSL 16;movk x8, 0x%04llX;BR x8;",(long long unsigned int)ret3,(long long unsigned int)ret2,(long long unsigned int)ret1,(long long unsigned int)aim3,(long long unsigned int)aim2,(long long unsigned int)aim1);
}


void generate_Springboard(){
   uint8_t machine_codes[300]; // This array is used to store the binary code
   char s[300];// This array is used to store instruction strings
    keystone_init();// Keystone is used to assemble instruction strings into binary code; this is its initialization.

    // The following code constructs instruction strings for the first-level trampoline,
    // assembles them into binary code, and writes the binary to the corresponding virtual address
    compile_asm_string("movz x9,0x789A,LSL 32;movk x8,0x5678,LSL 16", machine_codes, 100);// The two fixed instructions of the first-level trampoline
    for(int i = 1;i <= num_Mod_point;i++){
        if(mod_p[i].signal_handle) continue;// For signal handling, no trampoline is needed
        generate_string_Springboard(mod_p[i].per_aim_addr,s);// Generate the instruction string for the latter part of the jump trampoline and store it in `s`
        compile_asm_string(s, machine_codes, 100);// Assemble the instruction string in `s` and store the binary code in `machine_codes`
        
        uint8_t* addr_com = (uint8_t*)mod_p[i].com_aim_addr;
        for(int j = 0;j < 16;j++){
            addr_com[j] = machine_codes[j];
        }
    }
    
    // Start filling in the second-level trampoline. The process is similar to the one above
    for(int i = 1;i <= num_Mod_point;i++){
        if(mod_p[i].signal_handle) continue;
         uint32_t* taddr_per_32 = (uint32_t*)mod_p[i].per_aim_addr;
        (*taddr_per_32) = mod_p[i].insX8_org;
        taddr_per_32++;
        uint8_t* addr_per = (uint8_t*)taddr_per_32;
        generate_per_string_Springboard((uint64_t)mod_p[i].insSVC,s);
        compile_asm_string(s, machine_codes, 100);
        int per_sz = 44;
        for(int i = 0;i < per_sz;i++){
            addr_per[i] = machine_codes[i];
        }
    }
}



void generate_rewrite_bas(uint64_t aim_addr,char* s){
    sprintf(s,"movz x8, 0x%04llX;br x8;",(long long unsigned int)aim_addr);
}

void generate_rewrite_sp(uint64_t aim_addr,char* s){
    sprintf(s,"str x8,[sp, #-16]!;movz x8, 0x%04llX;br x8;",(long long unsigned int)aim_addr);
}



void start_rewrite(){// This function rewrites the `svc` instruction and the preceding `mov x8` instruction
    // so that execution jumps to our first-level trampoline
    char s[300];
    for(int i = 1;i <= num_Mod_point;i++){ // Generate the binary code to be overwritten here
        if(mod_p[i].signal_handle) continue;
        if( i >=  BASELINE){
            adrp_exchange(i);
            continue;
        }
        uint32_t* aim_addr = (uint32_t*)mod_p[i].com_aim_addr;
        generate_rewrite_bas((uint64_t)aim_addr,s);
        compile_asm_string(s, mod_p[i].machine_codes, 100);
    }
    for(int i = 1;i <= num_Mod_point;i++){
        if(mod_p[i].signal_handle){// For barcodes intercepted via signals, 
        //we replace them with a `brk` instruction or an illegal instruction
            uint32_t* addr_per  = (uint32_t*)mod_p[i].insSVC;
            if(siganlWhich == 1){
                *addr_per = 0xd4200000; //brk
            }
            else{
                *addr_per = 0xFFFFFFFF;// Illegal instruction
            }
            continue;
        }
        if(mod_p[i].insX8 == NULL){
            //puts("we recommend you open the first safety strategy,but even not,it is ok for most situation");
            uint32_t* addr_per  = (uint32_t*)mod_p[i].insSVC;
            if(siganlWhich == 1){
                *addr_per = 0xd4200000; //0xFFFFFFFF
            }
            else{
                *addr_per = 0xFFFFFFFF;// Illegal instruction
            }
            
            continue;
        }

        uint8_t* addr_per = (uint8_t*)mod_p[i].insX8;
        for(int j = 0;j < 4;j++){
             addr_per[j] =  mod_p[i].machine_codes[j];
        }
        addr_per  = (uint8_t*)mod_p[i].insSVC;
        for(int j = 0;j < 4;j++){
            addr_per[j] =  mod_p[i].machine_codes[j+4];
        }
    }

}

void do_rewrite_signal(){
    
     for(int i = 1;i <= num_Mod_point;i++){ 
        if(mod_p[i].signal_handle){
            uint32_t* addr_per  = (uint32_t*)mod_p[i].insSVC;// Fill in the positions of the SVC instructions
            if(siganlWhich == 1){
                *addr_per = 0xd4200000; 
            }
            else{
                *addr_per = 0xFFFFFFFF;
            }
            addr_per = (uint32_t*)mod_p[i].insX8;
            if(addr_per != NULL){// For the previously modified 'mov x8' instructions, restore their original values.
                *addr_per = mod_p[i].insX8_org;
            }
            continue;
        }
    }
    
}

__attribute__((visibility("hidden"))) void do_rewrite(){
    
    for(int i = 1; i <= ku_num; i++){// Iterate over each library, 
    //and for each shared library or executable, grant full permissions, since we are about to modify these segments
        assert(!mprotect((char *) ku[i].ex_bs_addr,(size_t) ku[i].ex_size,PROT_WRITE | PROT_READ | PROT_EXEC));
    }

    generate_AimAddress();// This function generates target addresses for both first-level and second-level trampolines
    generate_Springboard();// This function generates the bytecode for both first-level and second-level trampolines and writes it to the corresponding virtual addresses
    start_rewrite();// This function rewrites the `svc` instruction and the preceding `mov x8` instruction
    // so that execution jumps to our first-level trampoline
    keystone_free();
    for(int i = 1; i <= ku_num; i++){
	    assert(!mprotect((char *) ku[i].ex_bs_addr,(size_t) ku[i].ex_size,ku[i].ex_mem_prot));
        // Modifications complete, restore permissions

	}
}