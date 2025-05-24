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
#include <inttypes.h>
#include <signal.h>
#include <unistd.h>
#include <ucontext.h>
#include <setjmp.h>
#include <ctype.h>
#include "gotcha.h"


__attribute__((visibility("hidden"))) struct Mod_point mod_p[MAXN_MOD_POINT];
// num_Mod_point represents the total number of instructions that have been rewritten.
// num_2 represents the number of SVC instructions replaced using the non-signal interception method,
// which corresponds to the first two replacement strategies described in the paper.
__attribute__((visibility("hidden"))) int num_Mod_point = 0,num_2=0,num_sp=0;
__attribute__((visibility("hidden"))) int ku_num;
__attribute__((visibility("hidden"))) struct info_ku ku[MAX_KU_NUM];

bool siganlWhich = 0;// signalWhich indicates which signal is used for interception: 
// 0 means the default illegal instruction, and 1 means using brk for interception.

jmp_buf sy_env;

static int do_scan(void *data, const char *fmt, ...)
{
	struct disassembly_state *s = (struct disassembly_state *) data;
	va_list arg;
	va_start(arg, fmt);
	char buf[4096];
	vsprintf(buf, fmt, arg);
	if (!strncmp(buf, "SVC", 3) || !strncmp(buf, "svc", 3)) {// If the disassembled instruction is indeed an SVC instruction.
		uint32_t *ptr = (uint32_t *)(((uintptr_t) s->code) + s->off);
    	uint32_t inst = *ptr;
		// As a precaution, perform an additional check by reading the 32-bit value (instruction) at the location.
		// If it is an `svc #0` instruction, record the information.
	    if (inst == 0xd4000001) {
			num_Mod_point++;
			mod_p[num_Mod_point].insSVC = ptr;
			mod_p[num_Mod_point].off = s->off;
			mod_p[num_Mod_point].code = s->code;
		}
	}
	
	va_end(arg);
	return 0;
}


static void disassemble_and_rewrite(char *code, size_t code_size, int mem_prot __attribute__((unused)) )// Performs disassembly to locate SVC instruction information.
{
	struct disassembly_state s = { 0 };
	/* add PROT_WRITE to rewrite the code */
	assert(!mprotect(code, code_size, PROT_WRITE | PROT_READ | PROT_EXEC));
	disassemble_info disasm_info = { 0 };

	init_disassemble_info(&disasm_info, &s, do_scan);
	disasm_info.arch = bfd_arch_aarch64;
	disasm_info.mach = bfd_mach_aarch64;
	disasm_info.buffer = (bfd_byte *) code;
	disasm_info.buffer_length = code_size;
	disassemble_init_for_target(&disasm_info);
	disassembler_ftype disasm;
#if defined(DIS_ASM_VER_229) || defined(DIS_ASM_VER_239)
	disasm = disassembler(bfd_arch_aarch64, false, bfd_mach_aarch64, NULL);
#else
	bfd _bfd = { .arch_info = bfd_scan_arch("aarch64"), };
	assert(_bfd.arch_info);
	disasm = disassembler(&_bfd);
#endif
	s.code = code;
	while (s.off < code_size){
		s.off += disasm(s.off, &disasm_info);
		// During the disassembly of a single instruction, do_scan may be called multiple times depending on the instruction type, 
		// with each call disassembling only part of the instruction. However, s.off increases by 4 each time.
		if(safetySwitch[2]&&s.off < code_size - 4)
			do_add_aim_address((uint32_t*)(s.code + s.off));
		// If the second completeness check is enabled, determine whether the instruction is an absolute jump.
		// If it is, calculate the destination address and add it to the destination address array,
		// which can hold up to 300,000 entries.
	}
}
struct disassembly_state glob_s;
disassemble_info glob_disasm_info;
disassembler_ftype glob_disasm;
 
typedef struct {
  char *insn_buffer;// Temporary buffer to store the disassembled instruction string
  bool reenter;// Indicates whether this is a re-entry (false if first time)
  int order;// The number of times dis_fprintf has been called for the current instruction
  int mod_p; // Index of the current modification point
  char *code;// Address of the code currently being scanned
} stream_state;

static int dis_fprintf(void *stream, const char *fmt, ...) {
  stream_state *ss = (stream_state *)stream;
  ss->order++;
  va_list arg;
  va_start(arg, fmt);
  if (!ss->reenter) {
    vasprintf(&ss->insn_buffer, fmt, arg);
    ss->reenter = true;
  } else {
    char *tmp;
    vasprintf(&tmp, fmt, arg);
	if((tmp[0]== 'x'&& tmp[1]=='8')||(tmp[0]== 'w'&& tmp[1]=='8')){// If the current string is "x8" or "w8"
		if((strncmp(ss->insn_buffer, "mov", 3) == 0)&&(ss->order == 3) &&(mod_p[ss->mod_p].insX8 == NULL))// If it is a 'MOV x8, ...' instruction
		{
			mod_p[ss->mod_p].insX8 = (uint32_t*)ss->code;// Record the address of the instruction
			mod_p[ss->mod_p].insX8_org  = *((uint32_t*)ss->code); // Record the original instruction bytecode
		}
	}
	if(tmp[0] == '\t' || tmp[0] == '\n') {
		tmp[0] = ' ';
    }
    char *tmp2;
    asprintf(&tmp2, "%s%s", ss->insn_buffer, tmp);
    free(ss->insn_buffer);
    free(tmp);
    ss->insn_buffer = tmp2;
  }
  va_end(arg);
  return 0;
}

void disassemble_init(){
	#if defined(DIS_ASM_VER_229) || defined(DIS_ASM_VER_239)
	glob_disasm = disassembler(bfd_arch_aarch64, false, bfd_mach_aarch64, NULL);
	#else
	bfd _bfd = { .arch_info = bfd_scan_arch("aarch64"), };
	assert(_bfd.arch_info);
	glob_disasm = disassembler(&_bfd);
	#endif
}



void disassemble_instruction(char *code, char *result,int num_mod){
	// Disassemble this instruction; if it is indeed an assignment to the x8 register, 
	// the system call number will be recorded in mod_p[i].syscallnum.
	stream_state ss = {};
	ss.mod_p = num_mod;
	ss.order = 0;
	ss.code = code;
	init_disassemble_info(&glob_disasm_info, &ss, dis_fprintf);// The main disassembly logic is implemented in dis_fprintf.
	// As before, for the same instruction, dis_fprintf will be called multiple times,
	// each time parsing a small part of the instruction as a string.
	// For example, the instruction `MOV x8, #123` would trigger three calls:
	// the first for "MOV", the second for "x8", and so on.

	glob_disasm_info.arch = bfd_arch_aarch64;
	glob_disasm_info.mach = bfd_mach_aarch64;
	glob_disasm_info.buffer = (bfd_byte *) code;
	glob_disasm_info.buffer_length = 4;
	disassemble_init_for_target(&glob_disasm_info);
	glob_disasm(0, &glob_disasm_info);
    strcpy(result, ss.insn_buffer);
}

bool judge_foreword(char* ch) {
    if (strstr(ch, "stp") != NULL || strstr(ch, "str") != NULL) {
        if (strstr(ch, "sp") != NULL) {
            return true;
        }
    }

    for (int i = 0; i <= 8; ++i) {
        char reg[4];
        sprintf(reg, "x%d", i);  
        if (strstr(ch, reg) != NULL) {
            if (strstr(ch, "mov") != NULL || strstr(ch, "ldr") != NULL || strstr(ch, "ldp") != NULL) {
                return true;
            }
        }
    }

    return false;
}



// Function to extract the file name from a given path
char* getFileName(char* path) {
    
    char* fileName = strrchr(path, '/');
    if (fileName) {
        size_t len = strcspn(fileName + 1, "\n");
        fileName[len + 1] = '\0';
        return fileName + 1;
    }
    return path;
}

/**
  Extracts an immediate value from a string.
  @param input The input string, expected in the format "mov x8, #<immediate>"
  @return The extracted immediate value. Returns -1 if the input format is invalid.
*/
int extract_immediate(const char *input) {
    
    if (strncmp(input, "mov x8, #", 8) != 0) {
        return -1;
    }

    const char *immediate_start = input + 9;
    char *endptr;
    long immediate = strtol(immediate_start, &endptr, 0);

    if (endptr == immediate_start) {
        return -1;
    }

    return (int)immediate;
}


// Converts the instruction string to lowercase.
void to_lowercase(char* str) {
    while (*str) {
        *str = tolower(*str);
        str++;
    }
}

// Determines whether an instruction is a jump instruction.
bool judge_B_instruction(char* ins) {
    if (ins == NULL) {
        return false;
    }
   
    char ins_lower[30];
    strncpy(ins_lower, ins, sizeof(ins_lower) - 1);
    ins_lower[sizeof(ins_lower) - 1] = '\0'; 
    to_lowercase(ins_lower);
    
    const char* jump_instructions[] = {
        "b ","b.","bc.", "bl", "blr", "br", "cbnz", "cbz", "tbnz", "tbz","b\t"
    };

    for (int i = 0; i < (int)(sizeof(jump_instructions) / sizeof(jump_instructions[0])); i++) {
        if (strncmp(ins_lower, jump_instructions[i], strlen(jump_instructions[i])) == 0) {
            return true;
        }
    }

    return false;
}

/*
	This function is used to read the process image and record information about all loaded libraries as well as SVC (supervisor call) instructions.
*/
static void pre_prepare(void)
{
	FILE *fp;
	/* get memory mapping information from procfs */
	assert((fp = fopen("/proc/self/maps", "r")) != NULL);// Uses fopen to open the /proc/self/maps file, which contains the memory mapping information of the current process.
	{
		char buf[4096],buf2[4096];
		while (fgets(buf, sizeof(buf), fp) != NULL) {// read every line 
			/* we do not touch stack and vsyscall memory */
			strncpy(buf2, buf, sizeof(buf2) - 1);
			getfullku(buf2);
			if (((strstr(buf, "stack") == NULL) && (strstr(buf, "vsyscall") == NULL))) {// Skips lines that contain the strings "stack" or "vsyscall".
				int i = 0;
				char addr[65] = { 0 };
				char *c = strtok(buf, " ");// Splits this line by spaces.
				while (c != NULL) {
					switch (i) {
					case 0:
						strncpy(addr, c, sizeof(addr) - 1);// The first token after splitting is an address range, which includes a hyphen, e.g., 0x22222-0x333333.
						break;
					case 1:
						{
							int mem_prot = 0;// Indicates the permissions of this segment (VMA - Virtual Memory Area).
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
							if (mem_prot & PROT_EXEC) {
								size_t k;
								for (k = 0; k < strlen(addr); k++) {// Replaces the hyphen in the middle with '\0' to facilitate subsequent string operations.
									if (addr[k] == '-') {
										addr[k] = '\0';
										break;
									}
								}
								{
									int64_t from, to;// 'from' is the starting address of the segment, and 'to' is the ending address.
									from = strtol(&addr[0], NULL, 16);
									if (from == 0) {
										/*
										 * this is trampoline code.
										 * so skip it.
										 */
										break;
									}
									to = strtol(&addr[k + 1], NULL, 16);
									// Records the information of this segment.
									++ku_num;
									ku[ku_num].bs_addr = (int*)from;
									ku[ku_num].ex_bs_addr = (int*)from;
									ku[ku_num].ex_size = to - from;
									ku[ku_num].ex_mem_prot = mem_prot;
								}
							}
						}
						break;

						case 5:// The file system path of the library.
							{
								char* file_name = NULL;
								file_name = getFileName(c);
								strcpy(ku[ku_num].ku_name,file_name);
							}
						break;
					}
					if (i == 1 && (ku[ku_num].ku_name[0] != 0))
						break;
					if(i == 5) break;
					c = strtok(NULL, " ");
					i++;
				}
			}
		}
	}

	
	for(int i = 1; i <= ku_num; i++){// Iterates through each library, performing a linear scan on each shared library or executable to record all locations of SVC instructions.
		Elf64_Ehdr *tou = (Elf64_Ehdr *)ku[i].bs_addr;
		Elf64_Phdr *duanbiao = (Elf64_Phdr *)((char *)tou + tou->e_phoff);// The program header table of this library.
		ku[i].duanbiao = duanbiao;
		ku[i].tou = tou;
		if(strstr(ku[i].ku_name, "libkeystone.so")!=NULL) continue;// If the library name includes "libkeystone.so", it is skipped because this library does not contain system calls and is a disassembly tool used by ASC-Hook.
		if(strstr(ku[i].ku_name, "ASC_hook.so")!=NULL) continue;// This library is our own, so we also skip scanning it.
		disassemble_and_rewrite((char *) ku[i].ex_bs_addr,(size_t) ku[i].ex_size,ku[i].ex_mem_prot);// Performs disassembly to locate SVC instruction information.
	}


	// After locating the SVC instruction, we then disassemble the preceding instructions,
	// with the primary goal of finding the instruction that assigns a value to the x8 register.
	disassemble_init();
	for(int i = 1;i <= num_Mod_point; i++ ){
		uint32_t* now = mod_p[i].insSVC;
		int X8_p = 0;
		char ins[80];
		mod_p[i].signal_handle = false;
		mod_p[i].syscallnum = -1;
		for(int j = 1; j<=20 ; j++){// For each SVC instruction, we look back up to 20 instructions at most.
			now--;// 'now' points to the address of the instruction currently being disassembled in reverse.
			disassemble_instruction((char *)now,ins,i);// Disassemble this instruction; if it is indeed an assignment to the x8 register, 
			// the system call number will be recorded in mod_p[i].syscallnum.
			if(mod_p[i].syscallnum == -1){
				int numm = extract_immediate(ins);// Extract the corresponding system call number
				if(numm!= -1){
					mod_p[i].syscallnum = numm;
				}
			}
			if((mod_p[i].insX8 != NULL) && (X8_p == 0)){
				X8_p = j;// The 'mov x8' instruction is the j-th instruction before the SVC #0.
			}
			if((mod_p[i].insX8 == NULL) && judge_B_instruction(ins) && safetySwitch[1]){// If a jump-related instruction is found before the 'mov x8' and SVC, and completeness policy 1 is enabled, then signal-based interception is used.

				mod_p[i].signal_handle = 1;break;
			}
			if(j>=2&&mod_p[i].insX8 != NULL) break;// If the 'mov x8' instruction has already been found and more than two instructions have been disassembled, the task is complete and disassembly can stop.
		}

		if(mod_p[i].insX8 != NULL){// Found the instruction that assigns a value to the x8 register; we use the first two replacement strategies to perform the substitution.
			num_2++;
			// num_2 represents the number of SVC instructions replaced using the non-signal interception method,
			// which corresponds to the first two replacement strategies described in the paper.
		}
		if(mod_p[i].insX8 == NULL){// This means we did not find a 'mov x8' instruction
			if(safetySwitch[1]){// If security policy 1 is enabled, use signal-based interception for cases without 'mov x8'
				mod_p[i].signal_handle = 1;
			}
			else{
				//puts("if you saw this,This indicates the presence of a single SVC in the process image,We strongly recommend at least clocking in as the first completeness strategy");
			}
			
		}
	}

	for(int i = 1;i <= num_Mod_point; i++ ){
		for(int j = 1; j <= ku_num; j++){
			if((void*)mod_p[i].code == (void*)ku[j].bs_addr){
				mod_p[i].ku_name = ku[j].ku_name;
			}
		}
	}
	
	for(int i = 1; i <= ku_num; i++){
		assert(!mprotect((char *) ku[i].ex_bs_addr,(size_t) ku[i].ex_size,ku[i].ex_mem_prot));// After modifications are complete, restore permissions.
	}
	fclose(fp);
}

__attribute__((constructor(0xffff))) static void __ASC_hook_init(void)
{
	readSwitch();// This sets whether to enable the security feature; it is disabled by default on the syscallSwitch.config file.
	
	readBrkOr();// This reads the syscallSwitch.config file to determine whether to use brk or an illegal instruction to intercept system calls.

	pre_prepare();// This function is used to read the process image and record information about all loaded libraries as well as SVC (supervisor call) instructions.
	doSignalregister();// Register the signal handler.
	do_signal_intercept();//This is a branch that will only be entered when the third completeness policy is enabled.
	adrp_init();// This is a scheme for intercepting system calls using the ADRP instruction. For details, please refer to our paper. This section performs the related initialization.
	// However, this strategy is not very useful and is only a backup strategy, at least it is not needed on ARM64.

	if(safetySwitch[2])
		do_static_check();
	// Related to the second completeness policy, checks whether there is a jump target address directly between the two replaced instructions
	
	if(ti_run >= 1){// Since the third completeness policy was triggered and multiple executions were performed,
	// it's unnecessary to repeat everything; only rewriting signal_handle is sufficient.
		do_rewrite_signal();
	}
	else do_rewrite();// This function is executed for the first time
	load_hook_lib();
}
