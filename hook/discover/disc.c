/**
 * @file disc.c
 * @author Francesco Masci (francescomasci@outlook.com)
 * 
 * @brief This file implements the discover hooking mechanism for syscalls. It
 * 	  	  provides functions to set up and clean up the discover hooking mode, the
 *     	  mechanism to save and restore the original syscall table, and helper functions.
 * 
 * @version 1.0
 * @date 2026-01-26
 * 
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <asm/page.h>
#include <asm/ptrace.h>

#include "disc.h"
#include "sthack.h"
#include "../../sct.h"
#include "../../_syst.h"

#include "./lib/vtpmo.h"

extern int sys_vtpmo(unsigned long vaddr);

#define ADDRESS_MASK 		0xfffffffffffff000

#define START 				0xffffffff00000000ULL
#define MAX_ADDR			0xfffffffffff00000ULL
#define FIRST_NI_SYSCALL	134
#define SECOND_NI_SYSCALL	174
#define THIRD_NI_SYSCALL	182 
#define FOURTH_NI_SYSCALL	183
#define FIFTH_NI_SYSCALL	214	
#define SIXTH_NI_SYSCALL	215	
#define SEVENTH_NI_SYSCALL	236	

#define ENTRIES_TO_EXPLORE 256


static int good_area(unsigned long *);
static int validate_page(unsigned long *);
static void syscall_table_finder(void);
unsigned long ** get_syscall_table_addr(void);
unsigned long * get_original_syscall_addrs(void);

// Pointer to the located syscall table
static unsigned long **hacked_syscall_tbl = NULL;
// Array to save original syscall addresses
static unsigned long * original_syscall_addrs = NULL;

/**
 * @brief Get the syscall table address
 * 
 * @return unsigned long** Address of the syscall table
 */
unsigned long ** get_syscall_table_addr(void){
	return hacked_syscall_tbl;
}

/**
 * @brief Get the array of original syscall addresses
 * 
 * @return unsigned long* Array of original syscall addresses
 */
unsigned long * get_original_syscall_addrs(void){
	return original_syscall_addrs;
}

/**
 * @brief Checks if the area is good for syscall table
 * 
 * @param addr Address to check
 * @return int 1 if good, 0 otherwise
 */
static int good_area(unsigned long * addr){
	int i;
	for(i=1;i<FIRST_NI_SYSCALL;i++){
		if(addr[i] == addr[FIRST_NI_SYSCALL]) goto bad_area;
	}
	return 1;
bad_area:
	return 0;
}

/**
 * @brief Validates a page as syscall table
 * 
 * @param addr Address to validate
 * @return int 1 if valid, 0 otherwise
 */
static int validate_page(unsigned long *addr){
	int i = 0;
	unsigned long page 	= (unsigned long) addr;
	unsigned long new_page 	= (unsigned long) addr;
	for(; i < PAGE_SIZE; i+=sizeof(void*)){		
		new_page = page+i+SEVENTH_NI_SYSCALL*sizeof(void*);
			
		// If the table occupies 2 pages check if the second one is materialized in a frame
		if( 
			( (page+PAGE_SIZE) == (new_page & ADDRESS_MASK) )
			&& sys_vtpmo(new_page) == NO_MAP
		) 
			break;
		// go for patter matching
		addr = (unsigned long*) (page+i);
		if(
			   ( (addr[FIRST_NI_SYSCALL] & 0x3  ) == 0 )		
			   && (addr[FIRST_NI_SYSCALL] != 0x0 )			// not points to 0x0	
			   && (addr[FIRST_NI_SYSCALL] > 0xffffffff00000000 )	// not points to a locatio lower than 0xffffffff00000000	
	//&& ( (addr[FIRST_NI_SYSCALL] & START) == START ) 	
			&&   ( addr[FIRST_NI_SYSCALL] == addr[SECOND_NI_SYSCALL] )
			&&   ( addr[FIRST_NI_SYSCALL] == addr[THIRD_NI_SYSCALL]	 )	
			&&   ( addr[FIRST_NI_SYSCALL] == addr[FOURTH_NI_SYSCALL] )
			&&   ( addr[FIRST_NI_SYSCALL] == addr[FIFTH_NI_SYSCALL] )	
			&&   ( addr[FIRST_NI_SYSCALL] == addr[SIXTH_NI_SYSCALL] )
			&&   ( addr[FIRST_NI_SYSCALL] == addr[SEVENTH_NI_SYSCALL] )	
			&&   (good_area(addr))
		){
			hacked_syscall_tbl = (void*)(addr);
			return 1;
		}
	}
	return 0;
}

/**
 * @brief Finds the syscall table in memory
 * 
 * @return void Side effect: sets hacked_syscall_tbl if found
 */
static void syscall_table_finder(void){
	unsigned long k; // current page
	unsigned long candidate; // current page

	for(k=START; k < MAX_ADDR; k+=4096){	
		candidate = k;
		if((sys_vtpmo(candidate) != NO_MAP)){
			// check if candidate maintains the syscall_table
			if(validate_page( (unsigned long *)(candidate)) ) {
				break;
			}
		}
	}
	
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0) 
#define INST_LEN 5
char jump_inst[INST_LEN];
unsigned long x64_sys_call_addr;
char original_x64_sys_call_inst[INST_LEN];
int offset;
static struct kprobe kp_x64_sys_call = { .symbol_name = "x64_sys_call" };

/**
 * @brief Calls the original syscall from syscall table
 * 
 * @param regs CPU registers
 * @param nr Syscall number
 */
static inline void call(struct pt_regs *regs, unsigned int nr){
    	asm volatile("mov (%1, %0, 8), %%rax\n\t"
             "jmp __x86_indirect_thunk_rax\n\t"
             :
             : "r"((long)nr), "r"(hacked_syscall_tbl)
             : "rax");
}

#endif

/**
 * @brief Set up discover hooking mode
 * 
 * @return int 
 */
int setup_discover_hook(void) {
	
	int ret = 0;

	// Find syscall table
	syscall_table_finder();
	if(!hacked_syscall_tbl){
		PR_ERROR("Failed to find the sys_call_table\n");
		return -EINVAL;
	}
	PR_DEBUG("Syscall table found\n");

	// Save original syscall addresses
	original_syscall_addrs = kmalloc_array(SYSCALL_TABLE_SIZE, sizeof(unsigned long), GFP_KERNEL);
	if(!original_syscall_addrs) {
		PR_ERROR("Cannot allocate memory for saving original syscall addresses\n");
		return -ENOMEM;
	}
	memcpy(original_syscall_addrs, hacked_syscall_tbl, sizeof(unsigned long) * SYSCALL_TABLE_SIZE);
	PR_DEBUG("Original syscall addresses saved\n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
	ret = register_kprobe(&kp_x64_sys_call);
	if (ret < 0) {
		PR_ERROR("Cannot register kprobe for x64_sys_call\n");
		return ret;
	}
	PR_DEBUG("Kprobe for x64_sys_call registered\n");

	// Get x64_sys_call address
	x64_sys_call_addr = (unsigned long)kp_x64_sys_call.addr;
	unregister_kprobe(&kp_x64_sys_call);
	PR_DEBUG("Kprobe for x64_sys_call unregistered\n");

	// Save original instruction
	memcpy(original_x64_sys_call_inst, (unsigned char *)x64_sys_call_addr, INST_LEN);
	PR_DEBUG("Original instruction of x64_sys_call saved\n");

	// JMP opcode
	jump_inst[0] = 0xE9;
	// RIP points to the next instruction. Current instruction has length 5
	offset = (unsigned long)call - x64_sys_call_addr - INST_LEN;
	memcpy(jump_inst + 1, &offset, sizeof(int));
	PR_DEBUG("Jump instruction for x64_sys_call prepared\n");
	
#endif

	begin_syscall_table_hack();	
	PR_DEBUG("Syscall table hacking started\n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
//these kernel versions are configured to avoid the usage of the syscall table 
//this piece of code intercepts the activation of the syscall dispatcher and
//redirects control to the function that restores the usage of the syscall table 
//it may be possible that I did not check all the kernel cofigurations
//the user can add here whichever configuration he wants that avoids the
//usage of the syscall table while dispatching syscalls
	memcpy((unsigned char *)x64_sys_call_addr, jump_inst, INST_LEN);
	PR_DEBUG("Hack installed on x64_sys_call\n");
#endif
	end_syscall_table_hack();
	PR_DEBUG("Syscall table hacking ended\n");

	return 0;

}

/**
 * @brief Clean up discover hooking mode
 * 
 */
void cleanup_discover_hook(void) {
	
	begin_syscall_table_hack();
	PR_DEBUG("Syscall table hacking started for cleanup\n");

	// Restore original syscall table
	memcpy(hacked_syscall_tbl, original_syscall_addrs, sizeof(unsigned long) * SYSCALL_TABLE_SIZE);
	PR_DEBUG("Original syscall table restored\n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
	// Restore original x64_sys_call instruction
	memcpy((unsigned char *)x64_sys_call_addr, original_x64_sys_call_inst, INST_LEN);
	PR_DEBUG("Original instruction restored on x64_sys_call.\n");
#endif
	end_syscall_table_hack();
	PR_DEBUG("Syscall table hacking ended for cleanup\n");

	// Free allocated memory
	kfree(original_syscall_addrs);
	PR_DEBUG("Memory for original syscall addresses freed\n");
}
