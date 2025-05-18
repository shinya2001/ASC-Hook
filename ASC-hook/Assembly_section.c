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

extern void (*sy_print)(int);
extern void (*sy_exit)(void);
extern void (*sy_write)(int);
extern void (*sy_write2)(char*,long long);

extern void syscall_addr(void);
extern long enter_syscall(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);
extern void asm_syscall_hook(void);
typedef long (*syscall_fn_t)(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);
extern void (*signal_hook_function)(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t); 


static syscall_fn_t next_sys_call = NULL;

// Most of the functions in this file are written in assembly
// They are used to construct our third-level trampoline; start reading from the function `asm_syscall_hook`
void ____asm_impl(void){
    
		asm volatile (
	".globl enter_syscall \n\t"
	"enter_syscall:   \n\t"
    "ldr x8, [sp]   \n\t"
	"mov     x9, #0xdc   \n\t"// Special handling for `clone` begins here, due to stack issues in the newly created process
	"cmp     x8, x9   \n\t"
	"b.ne    skip_clone_check \n\t"
	"and     x9, x0, #0x100   \n\t"
	"cbz     x9, skip_clone_check \n\t"
	"str x30,[sp, #-16]!  \n\t"
	"ldr x9, [sp, #24]   \n\t"
	"ldr x10, [sp, #32]   \n\t"
	"ldr x11, [sp, #40]   \n\t"
	"ldr x12, [sp, #48]   \n\t"
	"ldr x13, [sp, #56]   \n\t"
	"ldr x14, [sp, #64]   \n\t"
	"ldr x15, [sp, #72]   \n\t"
	"ldr x16, [sp, #80]   \n\t"
	"ldr x17, [sp, #88]   \n\t"
	"ldr x30, [sp, #96]   \n\t"
	"svc #0 \n\t"
	"cmp     x0, 0   \n\t"
	"b.ne    return_addr \n\t"
	"ldr x8, [sp]   \n\t"
	"add sp, sp, #16   \n\t"
	"ret x8   \n\t"

	"skip_clone_check: \n\t"
	
	"mov     x9, #0x1b3   \n\t"// Special handling for `clone3` starts here, but since our kernel is only version 5.4 and doesn't support it, we haven't tested `clone3` yet
	"cmp     x8, x9   \n\t"
	"b.ne    syscall_addr \n\t"
	"and     x9, x0, #0x100   \n\t"
	"cbz     x9, syscall_addr \n\t"
	"str x30,[sp, #-16]!  \n\t"
	"ldr x9, [sp, #24]   \n\t"
	"ldr x10, [sp, #32]   \n\t"
	"ldr x11, [sp, #40]   \n\t"
	"ldr x12, [sp, #48]   \n\t"
	"ldr x13, [sp, #56]   \n\t"
	"ldr x14, [sp, #64]   \n\t"
	"ldr x15, [sp, #72]   \n\t"
	"ldr x16, [sp, #80]   \n\t"
	"ldr x17, [sp, #88]   \n\t"
	"ldr x30, [sp, #96]   \n\t"
	"svc #0 \n\t"
	"cmp     x0, 0   \n\t"
	"b.ne    return_addr \n\t"
	"ldr x8, [sp]   \n\t"
	"add sp, sp, #16   \n\t"
	"ret x8   \n\t"


	".globl syscall_addr \n\t"
	"syscall_addr: \n\t"
	"svc #0 \n\t"
	"ret \n\t"
	"return_addr: \n\t"
	"ldr x30, [sp], #16   \n\t" 
	"ret \n\t"
	);

	asm volatile (
	".globl asm_syscall_hook \n\t"
	"asm_syscall_hook: \n\t"


    "ldr x8, [sp, #8]   \n\t"     // Restore the value of x8 from the stack
	"cmp x8, #139 \n\t"  
	"b.eq do_rt_sigreturn  \n\t"

   
    "str x29, [sp, #-16]! \n\t" // Push the frame pointer register onto the stack to create a new stack frame
	"mov x29, sp  \n\t"

	// Save the context
	"stp x1, x2, [sp, #-16]!  \n\t"
	"stp x3, x4, [sp, #-16]!  \n\t"
	"stp x5, x6, [sp, #-16]!  \n\t"
	"stp x7, x8, [sp, #-16]!  \n\t"
	"stp x9, x10, [sp, #-16]!  \n\t"
	"stp x11, x12, [sp, #-16]!  \n\t"
	"stp x13, x14, [sp, #-16]!  \n\t"
	"stp x15, x16, [sp, #-16]!  \n\t"
	"stp x17, x30, [sp, #-16]!  \n\t"

    
    
// Pass function call arguments. `syscall_hook` takes 9 system call arguments.
// On ARM64, x0 to x7 can hold 8 arguments, so only one argument needs to be passed on the stack.
	"stp x17,x30, [sp, #-16]! \n\t" 
	"stp x15,x16, [sp, #-16]! \n\t" 
	"stp x13,x14, [sp, #-16]! \n\t" 
	"stp x11,x12, [sp, #-16]! \n\t"
	"stp x9,x10, [sp, #-16]! \n\t"  
	"ldr x10, [sp, #240] \n\t"
   	"stp x8,x10, [sp, #-16]! \n\t" 
	
	 
	"bl syscall_hook \n\t"// Actual handling

    "add sp, sp, #96   \n\t"  // Clear the last argument

    // Pop from stack and restore context
	"ldp x17, x30, [sp], #16   \n\t" 
	"ldp x15, x16, [sp], #16   \n\t"
	"ldp x13, x14, [sp], #16   \n\t"
	"ldp x11, x12, [sp], #16   \n\t"
	"ldp x9, x10, [sp], #16   \n\t"
	"ldp x7, x8, [sp], #16   \n\t"
	"ldp x5, x6, [sp], #16   \n\t"
	"ldp x3, x4, [sp], #16   \n\t"
	"ldp x1, x2, [sp], #16   \n\t"
	
	// Restore the FP (frame pointer) register and set SP back to its state before the function call
	"mov sp, x29  \n\t"  
	"ldr x29, [sp]  \n\t"

    "ldr x8, [sp,#16]  \n\t" // Restore the return address after executing the SVC instruction
    "add sp,sp,#32  \n\t"
	"ret x8\n\t"
	"do_rt_sigreturn:"
	"add sp,sp,#0x10  \n\t"
	"svc #0 \n\t"
	"sub sp,sp,#0x10  \n\t"
	"ldr x8, [sp]  \n\t"  
    "add sp,sp,#0x10  \n\t"
	"ret x8\n\t"
	);
}

static long (*hook_fn)(int64_t x0,int64_t x1,int64_t x2,int64_t x3,int64_t x4,int64_t x5,int64_t x6,int64_t x7,int64_t x8,int64_t x9,int64_t x10,int64_t x11,int64_t x12,int64_t x13,int64_t x14,int64_t x15,int64_t x16,int64_t x17,int64_t x30) = enter_syscall;

void init_syscall(){
	hook_fn = enter_syscall;
}

long syscall_hook(int64_t x0, int64_t x1,
		  int64_t x2, int64_t x3,
		  int64_t x4, int64_t x5,
		  int64_t x6, int64_t x7, 
          int64_t x8,int64_t retptr,int64_t x9,int64_t x10,int64_t x11,int64_t x12,int64_t x13,int64_t x14,int64_t x15,int64_t x16,int64_t x17,int64_t x30){
 	if (x8 == __NR_clone3) { // __NR_clone3 for ARM64
        uint64_t *ca = (uint64_t *) x0; /* struct clone_args */
        if (ca[0] /* flags */ & CLONE_VM) {
            ca[6] /* stack_size */ -= sizeof(uint64_t);
            *((uint64_t *) (ca[5] /* stack */ + ca[6] /* stack_size */)) = retptr; 
        }
    }

    if (x8 == __NR_clone) { // __NR_clone for ARM64
        if (x0 & CLONE_VM) { // pthread creation
            x1 -= 16;
            *((uint64_t *) (x1)) = retptr;
        }
    }
 return hook_fn(x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x30);
}

struct disassembly_state {
	char *code;
	size_t off;
};


__attribute__((visibility("hidden"))) void load_hook_lib(void)
{
	void *handle;
	{
		const char *filename;
		filename = getenv("LIBASCHOOK");
		if (!filename) {
			fprintf(stderr, "env LIBASCHOOK is empty, so skip to load a hook library\n");
			return;
		}

		handle = dlmopen(LM_ID_NEWLM, filename, RTLD_NOW | RTLD_LOCAL);
		if (!handle) {
			fprintf(stderr, "dlmopen failed: %s\n\n", dlerror());
			fprintf(stderr, "NOTE: this may occur when the compilation of your hook function library misses some specifications in LDFLAGS. or if you are using a C++ compiler, dlmopen may fail to find a symbol, and adding 'extern \"C\"' to the definition may resolve the issue.\n");
			exit(1);
		}
	}
	{
		int (*hook_init)(long, ...);
		hook_init = dlsym(handle, "__hook_init");
		void (*sysy_print)(int);
		sysy_print = dlsym(handle, "final_print");
		sy_print = sysy_print;
		sy_exit = dlsym(handle, "final_exit");
		sy_write = dlsym(handle, "final_write");
		sy_write2 = dlsym(handle, "final_write2");
		signal_hook_function = dlsym(handle, "final_signal_hook_function");
		assert(hook_init);
		assert(hook_init(0, &hook_fn) == 0);
	}
}