#define MAX_KU_NUM 500
#define MAXN_MOD_POINT 5000
#define BASE_FUNC_COMMON_F 4096 // Base address of the first-level trampoline
#define SIZE_FUNC_COMMON_F 16 // Each jump trampoline requires 16 bytes
#define PERSONAL_FUNC_BASE ((void *)0x100000000000LL)  // Base address of the second-level trampoline
#define SIZE_FUNC_PER_PER 44 // The number of bytes required for a second-level trampoline
#define PAGE_SIZE 4096

#define BASELINE 3800
// Start using `adrp` from this point

struct disassembly_state {
	char *code; // Starting address of this code segment
	size_t off;// Offset of the current instruction
	char *insn_buffer;// Buffer used to build the instruction string
	bool reenter; // Indicates whether this instruction has been entered multiple times
};
 
struct Mod_point{
	uint32_t* insSVC;// Virtual address of the SVC instruction
	size_t off;// Offset of the SVC instruction (for debugging)
	char *code;// Base address of the segment or library containing the modification point (for debugging)
	uint32_t* insX8;// Address of the `mov x8` instruction
	uint32_t  insX8_org;// Original value of the `mov x8` instruction, to be re-executed in the personalized trampoline
	bool signal_handle;// Indicates whether signal-based interception is used
	uint8_t machine_codes[14];// Stores the binary code that replaces the original instructions (e.g., `mov x8`, `svc 0`) in the main program
    uint64_t com_aim_addr;// Target address of the first-level trampoline
    uint64_t per_aim_addr;// Target address of the second-level personalized trampoline
	int syscallnum;// System call number
	char* ku_name;// Name of the library
};

// This structure holds all relevant information for a library or an executable file
struct info_ku{
	int* bs_addr; // Base address of the library
	int* ex_bs_addr;// Base address of the executable segment
	size_t ex_size; // Size of the executable segment in virtual memory
	Elf64_Ehdr *tou;// ELF header
	Elf64_Phdr *duanbiao; // Program header table
	int ex_mem_prot; // Memory protection flags for the executable segment
	char ku_name[30];// Name of the library
};
extern int ku_num;
extern int ti_run;
extern int full_ku_num;
extern struct info_ku ku[MAX_KU_NUM];
extern struct info_ku fill_Ku[MAX_KU_NUM];
extern struct Mod_point mod_p[MAXN_MOD_POINT];
extern bool safetySwitch[6];
extern int num_Mod_point,num_2;
extern bool siganlWhich;// Specifies which signal-based interception method to use
//: 0 for default illegal instruction, 1 for interception via `brk`
extern void do_rewrite();
extern void do_rewrite_signal();
extern void init_syscall();
extern void asm_syscall_hook();
extern void load_hook_lib();
extern void doSignalregister();
extern void do_signal_intercept();
extern void readSwitch();
extern void readBrkOr();
extern void (*sy_print)(int);
extern void (*sy_write)(int);
extern void (*sy_write2)(char*,long long);
extern void (*signal_hook_function)(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);
extern void do_add_aim_address(uint32_t*);
extern void getfullku(char*);
extern char* getFileName(char*);
extern void adrp_init();
extern int compare(const void*, const void*);
extern void adrp_alloc_adress(int);
extern uint64_t* lower_bound(uint64_t*, uint64_t*, uint64_t);
extern void adrp_exchange(int);
extern void do_static_check();
//extern void (*signal_hook_function)(void); 