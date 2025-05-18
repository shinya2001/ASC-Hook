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
#include <string.h>
#include "gotcha.h"

void (*sy_print)(int);
void (*sy_exit)(void);
void (*sy_write)(int);
void (*sy_write2)(char*,long long);
void (*signal_hook_function)(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t); 
//void (*signal_hook_function)(void);
jmp_buf signal_env;
int ti_run = 0;
bool safetySwitch[6];// Flag indicating whether our security policy is enabled

bool syscallnum_content[700];


#define BLR_MASK 0xFFFFFC1F
#define BLR_OPCODE 0xD63F0000

// Function to check whether an instruction is a BLR instruction and extract the register number
int is_blr_instruction(uint32_t* addr, uint32_t *reg) {
    uint32_t instruction = *addr;
    if ((instruction & BLR_MASK) == BLR_OPCODE) {
        *reg = (instruction >> 5) & 0x1F;
        return 1; 
    }
    return 0;
}

// Check whether the address `now` and the address 20 instructions before it are within the library's code segment
bool checkInKu(unsigned long long now){
    bool ans = 0;
    for(int i = 1; i <= ku_num; i++){
		unsigned long long l = (unsigned long long)ku[i].ex_bs_addr, r = (unsigned long long)(ku[i].ex_bs_addr + ku[i].ex_size);
        if( now >= l && now <= r){
            ans = 1;break;
        }
	}
    if(ans == 0){
        return 0;
    }
    ans = 0;
    now -= 80;
    for(int i = 1; i <= ku_num; i++){
		unsigned long long l = (unsigned long long)ku[i].ex_bs_addr, r = (unsigned long long)(ku[i].ex_bs_addr + ku[i].ex_size);
        if( now >= l && now <= r){
            ans = 1;break;
        }
	}
    return ans;
}

void judge_svc(uint32_t* f_address){
   uint32_t* now=f_address;
   if(!checkInKu((unsigned long long)now)){
        return;
   }
  
   // Ensure `f_address` is within the code segment
    for(int i = 0; i <= 20; i++){
        if((*now)==0xd61f0100){
            long long off = 0xfffffffff,ansku = -1;
            for(int j = 1; j <= ku_num; j++){
		        if((unsigned long long)now > (unsigned long long)ku[j].bs_addr){
                    long long dis = (long long) now - (long long)ku[j].bs_addr;
                    if(dis < off && dis > 0){
                        off = dis;
                        ansku = j;
                    }
                }
			}
            sy_write2(ku[ansku].ku_name,off);
            break;
        }
        now++;
    }
}

void BusError_handler(int sig __attribute__((unused)), siginfo_t *info __attribute__((unused)), void *ucontext) {
    // Handler function for Bus Error
	ucontext_t *context = (ucontext_t *)ucontext;
    greg_t *regs = (greg_t*)context->uc_mcontext.regs;
	int syscall_num = regs[8];long long x30 = regs[30],id = 35;
	sy_write(syscall_num);// Log the invalid system call number to an external configuration file
    if(is_blr_instruction((uint32_t*)(x30-4),(uint32_t*)(&id))){
        judge_svc((uint32_t*)regs[id]);
        // Perform further analysis based on the method described in the paper to see if we can pinpoint the address of the SVC instruction
    }
    for(int i = 1;i <= num_Mod_point;i++){
        if(mod_p[i].syscallnum == syscall_num){
            // Also add the location information of newly signal-intercepted SVC instructions to the syscallplace.config file
			sy_write2(mod_p[i].ku_name,mod_p[i].off);
        }
    }
    longjmp(signal_env, ++ti_run);
	//sy_exit();
}

void BusError_haSegmentError_handlerndler(int sig __attribute__((unused)), siginfo_t *info __attribute__((unused)), void *ucontext) {
	// Segmentation fault handling process, largely the same as the bus error handling process
    ucontext_t *context = (ucontext_t *)ucontext;
    greg_t *regs = (greg_t*)context->uc_mcontext.regs;
	int syscall_num = regs[8]; long long x30 = regs[30],id = 35;
	sy_write(syscall_num);
    if(is_blr_instruction((uint32_t*)(x30-4),(uint32_t*)(&id))){
        judge_svc((uint32_t*)regs[id]);
    }
	for(int i = 1;i <= num_Mod_point;i++){
        if(mod_p[i].syscallnum == syscall_num){
            sy_write2(mod_p[i].ku_name,mod_p[i].off);
        }
    }
    longjmp(signal_env, ++ti_run);
}


void handle_sigtrap(int sig __attribute__((unused)), siginfo_t *info __attribute__((unused)), void *ucontext) {	
    // Signal handler function for segmentation faults and signals triggered by `brk`
    ucontext_t *context = (ucontext_t *)ucontext;
    greg_t *regs = (greg_t*)context->uc_mcontext.regs;
	context->uc_mcontext.pc += 4;
    // Call the user-defined function.
    signal_hook_function(regs[0],regs[1],regs[2],regs[3],regs[4],regs[5],regs[6],regs[7],regs[8],regs[9],regs[10],regs[11],regs[12],regs[13],regs[14],regs[15],regs[16],regs[17],regs[30]);
    unsigned long long tmp_stack = 0;
	if(regs[8] == 0xdc ){// This is special handling for `clone`
		 tmp_stack = regs[1];
		 __asm__ __volatile__(
            "mov %[result], sp"
            : [result] "=r" (regs[1])
        );
	}
	if((regs[8] == 0xdc )&&(regs[0] & 0x100)){// This is also part of the handling for `clone`
		 asm volatile (
        "mov x0, %0 \n\t"
        "mov x1, %1 \n\t"
        "mov x2, %2 \n\t"
        "mov x3, %3 \n\t"
        "mov x4, %4 \n\t"
        "mov x5, %5 \n\t"
        "mov x6, %6 \n\t"
        "mov x7, %7 \n\t"
        "mov x8, %8 \n\t"
        : 
        : "r"(regs[0]), "r"(regs[1]), "r"(regs[2]), "r"(regs[3]), "r"(regs[4]), "r"(regs[5]), "r"(regs[6]), "r"(regs[7]), "r"(regs[8])
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8" 
   	 );
   		// Execute the SVC instruction
   	 asm volatile (
        "svc #0 \n\t"
   	 );
    
       asm volatile (
        "ldr x9, %0 \n\t"      
        "str x0, [x9] \n\t"   
        "str x1, [x9, #8] \n\t" 
        "str x2, [x9, #16] \n\t" 
        "str x3, [x9, #24] \n\t" 
        "str x4, [x9, #32] \n\t" 
        "str x5, [x9, #40] \n\t"
        "str x6, [x9, #48] \n\t" 
        "str x7, [x9, #56] \n\t" 
        "str x8, [x9, #64] \n\t"
        : 
        : "m"(regs)
        : "x9", "memory"
    	);
		if(regs[0] == 0){// Child process
			context->uc_mcontext.sp = tmp_stack;
			//exit(0);
		}
		else{// Parent process
			regs[1] = tmp_stack;
		}
		return;
		}
   		 asm volatile (
       	 "mov x0, %0 \n\t"
       	 "mov x1, %1 \n\t"
       	 "mov x2, %2 \n\t"
       	 "mov x3, %3 \n\t"
        "mov x4, %4 \n\t"
        "mov x5, %5 \n\t"
        "mov x6, %6 \n\t"
        "mov x7, %7 \n\t"
        "mov x8, %8 \n\t"
        : 
        : "r"(regs[0]), "r"(regs[1]), "r"(regs[2]), "r"(regs[3]), "r"(regs[4]), "r"(regs[5]), "r"(regs[6]), "r"(regs[7]), "r"(regs[8])
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8"
    	);
    asm volatile (
        "svc #0 \n\t"
    );
    
       asm volatile (
        "ldr x9, %0 \n\t"      
        "str x0, [x9] \n\t"    
        "str x1, [x9, #8] \n\t" 
        "str x2, [x9, #16] \n\t" 
        "str x3, [x9, #24] \n\t" 
        "str x4, [x9, #32] \n\t" 
        "str x5, [x9, #40] \n\t" 
        "str x6, [x9, #48] \n\t" 
        "str x7, [x9, #56] \n\t" 
        "str x8, [x9, #64] \n\t" 
        : 
        : "m"(regs)
        : "x9", "memory"
    );
}

void doSignalregister(){// Register the signal handler.
	struct sigaction sa,sa2,sa3; 
    if(safetySwitch[3]){
        sa.sa_sigaction = BusError_handler;
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGBUS, &sa, NULL);// This is a bus error, which falls under completeness policy 3.
	    
        sa2.sa_sigaction = BusError_haSegmentError_handlerndler;
        sa2.sa_flags = SA_SIGINFO;
        sigemptyset(&sa2.sa_mask);
        sigaction(SIGSEGV, &sa2, NULL);// This is a segmentation fault, which also falls under completeness policy 3.
    }
    if(safetySwitch[1]||safetySwitch[2]||safetySwitch[3]){
        sa3.sa_sigaction = handle_sigtrap;
        sa3.sa_flags = SA_SIGINFO;
        sigemptyset(&sa3.sa_mask);
        if(siganlWhich){
	        sigaction(SIGTRAP, &sa3, NULL);//brk
        }
        else{
            sigaction(SIGILL, &sa3, NULL);// Signal for illegal instruction.
        }
    }
}

void syscall_num_config_read(){// This function reads the syscallnum.config file and extracts the system call numbers into the syscallnum_content[] array.
    FILE *file;
    #define MAX_BUFFER_SIZE 1024
     char buffer[MAX_BUFFER_SIZE];
    char *token;
    const char *filename = "syscallSwitch.config";
    int syscall_num;

    // Open the file
    file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening file");
        exit(0);
    }
    // Skip the first two lines
    if (fgets(buffer, MAX_BUFFER_SIZE, file) == NULL) {
        perror("Error reading file");
        fclose(file);
        return;
    }
    if (fgets(buffer, MAX_BUFFER_SIZE, file) == NULL) {
        perror("Error reading file");
        fclose(file);
        return;
    }

    // Read the content of the file into the buffer
    if (fgets(buffer, MAX_BUFFER_SIZE, file) == NULL) {
        perror("Error reading file");
        fclose(file);
        return;
    }

    // Close the file
    fclose(file);
    memset(syscallnum_content,0,sizeof(syscallnum_content));
     // Use comma to separate the strings
    // Skip "system call number need to be pass:"
    char *prefix = "system call number need to be pass:";
    char *syscalls = strstr(buffer, prefix);
    if (syscalls == NULL) {
        fprintf(stderr, "Invalid config format\n");
        return;
    }

     // Skip the prefix part
    syscalls += strlen(prefix);

    // Skip leading spaces
    while (*syscalls == ' ') syscalls++;

    token = strtok(syscalls, ",");
    while (token != NULL) {
        syscall_num = atoi(token); // Convert the string to an integer
        if(syscall_num>=0 && syscall_num <= 699) 
            syscallnum_content[syscall_num] = 1;
        token = strtok(NULL, ",");
    }
}

void do_mark(){
    for(int i = 1;i <= num_Mod_point;i++){
        if((mod_p[i].syscallnum>=0) && (mod_p[i].syscallnum<=700)){
            if(syscallnum_content[mod_p[i].syscallnum]){
                mod_p[i].signal_handle = 1;
            }
        }
    }
}


/*
        This function reads the syscallSwitch.config file and extracts the first line,
        which contains the status of three switches as either "on" or "off".
        "on" means enabled, and "off" means disabled.
        The results are stored in the safetySwitch array.
*/
void readSwitch(){// This sets whether to enable the security feature; it is disabled by default on the syscallSwitch.config file.
   
   
   
    memset(safetySwitch,0,sizeof(safetySwitch));
    FILE *file = fopen("./syscallSwitch.config", "r");
    
    if (file == NULL) {//"If this file is not set, then all security policies are disabled by default.
        return;
    }

    char buffer[256];
    if (fgets(buffer, sizeof(buffer), file) == NULL) {
        
        fclose(file);
        return;
    }
    fclose(file);

    //Remove line breaks
    buffer[strcspn(buffer, "\n")] = 0;
    char *prefix = "safety switch:";
    if (strncmp(buffer, prefix, strlen(prefix)) != 0) {//The format is fixed and must start with 'safety switch:'. If it doesn't start with this, all switches are considered disabled by default.
        fprintf(stderr, "Invalid config format\n");
        return;
    }

    // Extract on, off status
    char *config = buffer + strlen(prefix);
    while (*config == ' ') config++; // Skip leading spaces
    char *token = strtok(config, ",");
    for (int i = 1; i <= 3; i++) {
        if (token == NULL) {
            fprintf(stderr, "Invalid config format\n");
            return;
        }
        safetySwitch[i] = (strcmp(token, "on") == 0) ? 1 : 0;
        token = strtok(NULL, ",");
    }

    
    return;
}

void readBrkOr(){// This reads the syscallSwitch.config file to determine whether to use brk or an illegal instruction to intercept system calls.
    FILE *file = fopen("./syscallSwitch.config", "r");
    if (file == NULL) {
        perror("Failed to open file");
        exit(1);
    }

    char line[1024];
    int lineCount = 0;
    int syscallNumber = -1;

    while (fgets(line, sizeof(line), file) != NULL) {
        lineCount++;

        // Skip the first three lines
        if (lineCount <= 3) {
            continue;
        }

        // Check if the line contains "use brk or Illegal instruction:"
        if (strstr(line, "use brk or Illegal instruction:") != NULL) {
            // Find the position of the colon
            char *colonPos = strchr(line, ':');
            if (colonPos != NULL) {
                // Get the number after the colon
                syscallNumber = atoi(colonPos + 1);
            }
            break;
        }
    }
    if((syscallNumber == 0) || (syscallNumber == 1)){
        siganlWhich = syscallNumber;
        // signalWhich indicates which signal is used for interception: 
        // 0 means the default illegal instruction, and 1 means using brk for interception.

    }
}

void syscall_place_config_read(){// This function reads the syscallplace.config file, retrieves the library names and offsets, and directly marks them to indicate that we need to intercept them using signals.
    FILE *file;
    char *filename = "./syscallplace.config";
    char buffer[256];
    //int exists = 0;

    // Open the file (create the file if it doesn't exist)
    file = fopen(filename, "a+");
    if (!file) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    // Check if the same library name and offset already exist
    while (fgets(buffer, sizeof(buffer), file)) {
        char file_param1[256];
        long long file_param2;

        // Parse each line, assuming the format is "library_name offset"
        if (sscanf(buffer, "%s %lld", file_param1, &file_param2) == 2) {
            for(int i = 1;i <= num_Mod_point;i++){
        
            if (strcmp(file_param1,  mod_p[i].ku_name) == 0 && (size_t)file_param2 ==  mod_p[i].off) {
                mod_p[i].signal_handle = 1; // Here, we mark this modification point (one mod_p[i] corresponds to one svc instruction). We replace the interception scheme with a signal-based interception.
                break;
            }
         }
        }
    }
}

#define MAX_LINE_LENGTH 1024
#define MAX_ARGS 128

void read_config(char *filename, char *program, char *args[]) {//This is used to obtain the command to execute again, meaning the user needs to put the command for the application in the second line of the syscallSwitch.config file
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    char line[MAX_LINE_LENGTH];
     // Read and skip the first line
    if (fgets(line, sizeof(line), file) == NULL) {
        fprintf(stderr, "Error reading from config file\n");
        exit(EXIT_FAILURE);//Similarly, this should terminate.
    }
    if (fgets(line, sizeof(line), file) != NULL) {
       // Remove the newline character
        line[strcspn(line, "\n")] = 0;
         // Skip the preceding "Running instructions including parameters:"
        char *prefix = "Running instructions including parameters:";
        char *instruction = strstr(line, prefix);
        if (instruction == NULL) {
            fprintf(stderr, "Invalid config format\n");
            exit(EXIT_FAILURE);
        }

         // Skip the prefix part
        instruction += strlen(prefix);

        // Skip leading spaces
        while (*instruction == ' ') instruction++;

        // Extract the actual command and arguments
    // Parse the program path and arguments
        char *token = strtok(instruction, " ");
        int i = 0;
        while (token != NULL && i < MAX_ARGS - 1) {
            args[i++] = token;
            token = strtok(NULL, " ");
        }
        args[i] = NULL;
        strcpy(program, args[0]);
    } else {
        fprintf(stderr, "Error reading from config file\n");
        exit(EXIT_FAILURE);
    }

    fclose(file);
}

void do_signal_intercept(){//This is a branch that will only be entered when the third completeness policy is enabled.
  
    int ti = setjmp(signal_env);// This sets the position for longjmp to jump back to, with longjmp being set in the interrupt handlers for segmentation faults and bus errors.
    if (ti <= 10) {
        if(ti >= 1){// Here, we will use the exec system call to re-execute our application.
            init_syscall(); // This function makes the function pointer hook_fn point back to enter_syscall, directly executing the svc instruction. Later, the user-defined hook_fn will be reloaded in the load function.
            char *config_file = "syscallSwitch.config";
            char program[MAX_LINE_LENGTH];
            char *args[MAX_ARGS];
            read_config(config_file, program, args);
            execvp(program, args);
            // If execvp fails, the following line will be executed.
            perror("execvp failed");
            exit(0);
        }
        syscall_num_config_read();// This function reads the syscallnum.config file and extracts the system call numbers into the syscallnum_content[] array.
        if(safetySwitch[3])// If our third completeness policy is enabled
            syscall_place_config_read();// This function reads the syscallplace.config file, retrieves the library names and offsets, and directly marks them to indicate that we need to intercept them using signals.
        
    } else {
        exit(0);
    }
    if(safetySwitch[3])// If our third completeness policy is enabled
        do_mark();// Based on the system call number, mark all those that need to be intercepted by signals as using signals for interception
   
}