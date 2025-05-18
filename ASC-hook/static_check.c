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
#define MAX_AIM_ADRESSS 3000000
uint64_t aim_address[MAX_AIM_ADRESSS],addres_hash[MAX_AIM_ADRESSS],aim_address_num;


int64_t sign_extend(int32_t imm26) {
    // If the immediate is negative, extend the sign
    if (imm26 & (1 << 25)) {
        return imm26 | ~((1 << 26) - 1);
    } else {
        return imm26 & ((1 << 26) - 1);
    }
}

// Function to check if an instruction is a B instruction and return the target address
bool is_b_instruction(uint32_t instruction, uint64_t pc, uint64_t *target_address) {
    // Check if the instruction is a B instruction
    if ((instruction & 0x7C000000) == 0x14000000) {
        // Extract the 26-bit immediate value
        int32_t imm26 = instruction & 0x03FFFFFF;
        // Sign-extend the immediate value
        int64_t offset = sign_extend(imm26) << 2;
        // Calculate the target address
        *target_address = pc + offset;
        return true;
    }
    return false;
}

// Function to check if an instruction is a B.cond instruction and return the target address
bool is_b_cond_instruction(uint32_t instruction, uint64_t pc, uint64_t *target_address) {
    // Check if the instruction is a B.cond instruction
    if ((instruction & 0xFF000010) == 0x54000000) {
        // Extract the 19-bit immediate value
        int32_t imm19 = (instruction >> 5) & 0x7FFFF;
        // Sign-extend the immediate value
        int64_t offset = sign_extend(imm19) << 2;
        // Calculate the target address
        *target_address = pc + offset;
        return true;
    }
    return false;
}

// Function to check if an instruction is a BC.cond instruction and return the target address
bool is_bc_cond_instruction(uint32_t instruction, uint64_t pc, uint64_t *target_address) {
    // Check if the instruction is a BC.cond instruction
    if ((instruction & 0xFF000010) == 0x54000010) {
        // Extract the 19-bit immediate value
        int32_t imm19 = (instruction >> 5) & 0x7FFFF;
        // Sign-extend the immediate value
        int64_t offset = sign_extend(imm19) << 2;
        // Calculate the target address
        *target_address = pc + offset;
        return true;
    }
    return false;
}

// Function to check if an instruction is a BL instruction and return the target address
bool is_bl_instruction(uint32_t instruction, uint64_t pc, uint64_t *target_address) {
    // Check if the instruction is a BL instruction
    if ((instruction & 0xFC000000) == 0x94000000) {
        // Extract the 26-bit immediate value
        int32_t imm26 = instruction & 0x03FFFFFF;
        // Sign-extend the immediate value
        int64_t offset = sign_extend(imm26) << 2;
        // Calculate the target address
        *target_address = pc + offset;
        return true;
    }
    return false;
}

// Function to check if an instruction is a CBZ instruction and return the target address
bool is_cbz_instruction(uint32_t instruction, uint64_t pc, uint64_t *target_address) {
    // Check if the instruction is a CBZ instruction
    if ((instruction & 0x7F000000) == 0x34000000) {
        // Extract the 19-bit immediate value
        int32_t imm19 = (instruction >> 5) & 0x7FFFF;
        // Sign-extend the immediate value
        int64_t offset = sign_extend(imm19) << 2;
        // Calculate the target address
        *target_address = pc + offset;
        return true;
    }
    return false;
}

// Function to check if an instruction is a CBNZ instruction and return the target address
bool is_cbnz_instruction(uint32_t instruction, uint64_t pc, uint64_t *target_address) {
    // Check if the instruction is a CBNZ instruction
    if ((instruction & 0x7F000000) == 0x35000000) {
        // Extract the 19-bit immediate value
        int32_t imm19 = (instruction >> 5) & 0x7FFFF;
        // Sign-extend the immediate value
        int64_t offset = sign_extend(imm19) << 2;
        // Calculate the target address
        *target_address = pc + offset;
        return true;
    }
    return false;
}

// Function to check if an instruction is a TBNZ instruction and return the target address
bool is_tbnz_instruction(uint32_t instruction, uint64_t pc, uint64_t *target_address) {
    // Check if the instruction is a TBNZ instruction
    if ((instruction & 0x7F000000) == 0x37000000) {
        // Extract the 14-bit immediate value
        int32_t imm14 = (instruction >> 5) & 0x3FFF;
        // Sign-extend the immediate value
        int64_t offset = sign_extend(imm14) << 2;
        // Calculate the target address
        *target_address = pc + offset;
        return true;
    }
    return false;
}

// Function to check if an instruction is a TBZ instruction and return the target address
bool is_tbz_instruction(uint32_t instruction, uint64_t pc, uint64_t *target_address) {
    // Check if the instruction is a TBZ instruction
    if ((instruction & 0x7F000000) == 0x36000000) {
        // Extract the 14-bit immediate value
        int32_t imm14 = (instruction >> 5) & 0x3FFF;
        // Sign-extend the immediate value
        int64_t offset = sign_extend(imm14) << 2;
        // Calculate the target address
        *target_address = pc + offset;
        return true;
    }
    return false;
}

/*
 Determine whether this is an absolute jump instruction. 
 If so, calculate the target address and add it to the target address array. 
 The maximum number of target addresses is 300,000.
*/
void do_add_aim_address(uint32_t* now)
{
    //zxddsadasd++;
    uint32_t instruction = *now; // Example B instruction
    uint64_t pc = (uint64_t)now; // Example PC value
    uint64_t target_address = 0;
   
    if (is_b_instruction(instruction, pc, &target_address)) {
        aim_address[++aim_address_num] = target_address;
    } 
    else if (is_b_cond_instruction(instruction, pc, &target_address)) {
        aim_address[++aim_address_num] = target_address;
    }
    else if (is_bc_cond_instruction(instruction, pc, &target_address)) {
        aim_address[++aim_address_num] = target_address;
    }
    else if (is_bl_instruction(instruction, pc, &target_address)) {
        aim_address[++aim_address_num] = target_address;
    }
    else if (is_cbnz_instruction(instruction, pc, &target_address)) {
        aim_address[++aim_address_num] = target_address;
    }
    else if (is_cbz_instruction(instruction, pc, &target_address)) {
        aim_address[++aim_address_num] = target_address;
    }
    else if (is_tbnz_instruction(instruction, pc, &target_address)) {
        aim_address[++aim_address_num] = target_address;
    }
    else if (is_tbz_instruction(instruction, pc, &target_address)) {
        aim_address[++aim_address_num] = target_address;
    }
}

// Comparison function for qsort, used to sort in ascending order
int compare(const void *a, const void *b) {
    if (*(uint64_t*)a < *(uint64_t*)b) return -1;
    if (*(uint64_t*)a > *(uint64_t*)b) return 1;
    return 0;
}

// unique function to remove duplicate elements
int unique(uint64_t* arr, int n) {
    if (n == 0) return 0;
    int j = 0;  
    for (int i = 1; i < n; i++) {
        if (arr[i] != arr[j]) {
            j++;
            arr[j] = arr[i];
        }
    }
    return j + 1;  // Return the new length of the array
}

// lower_bound function
uint64_t* lower_bound(uint64_t* begin, uint64_t* end, uint64_t value) {
    uint64_t* left = begin;
    uint64_t* right = end;
    while (left < right) {
        uint64_t* mid = left + (right - left) / 2;
        if (*mid < value)
            left = mid + 1;
        else
            right = mid;
    }
    return left;
}


void do_static_check(){
    // Remove duplicate addresses from the target address list
    qsort(aim_address + 1, aim_address_num, sizeof(uint64_t), compare);
    int size = unique(aim_address + 1, aim_address_num);

   for(int i = 1;i <= num_Mod_point;i++){// This is likely checking whether the target address of the jump is an SVC instruction
// If so, use signal-based interception
        if(mod_p[i].signal_handle) continue;
        uint64_t x = (uint64_t)mod_p[i].insSVC;
        uint64_t* pos = lower_bound(aim_address + 1, aim_address + 1 + size, x);
        if(*pos == x){
           mod_p[i].signal_handle = 1;
        }
    }

    // Add the addresses of our replaced instructions to the aim_address array as well,
    // so we can later check whether a jump target falls between the two replaced instructions

    for(int i = 1;i <= num_Mod_point;i++){
        if(mod_p[i].signal_handle) continue;
        if(mod_p[i].insX8 == NULL) continue;
        uint64_t x = (uint64_t)mod_p[i].insSVC; 
        aim_address[++aim_address_num]= x;
        x = (uint64_t)mod_p[i].insX8;
        aim_address[++aim_address_num]= x;
    }
    qsort(aim_address + 1, aim_address_num, sizeof(uint64_t), compare);
    size = unique(aim_address + 1, aim_address_num);
    // Remove duplicate elements

    for(int i = 1;i <= num_Mod_point;i++){ // This is where we formally check whether there is an indirect jump address between the two replaced instructions
        if(mod_p[i].signal_handle) continue;
        if(mod_p[i].insX8 == NULL) continue;
        uint64_t x = (uint64_t)mod_p[i].insSVC;// The virtual address of the current SVC instruction
        uint64_t* pos = lower_bound(aim_address + 1, aim_address + 1 + size, x);
        x = (uint64_t)mod_p[i].insX8;// The virtual address of the current SVC instruction
        uint64_t* pos2 = lower_bound(aim_address + 1, aim_address + 1 + size, x);
        int hhhh = pos-pos2;  
        if(hhhh>= 2){
            mod_p[i].signal_handle = 1 ;
        }
    }
}