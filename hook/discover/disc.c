/**
 * @file disc.c
 * @author Francesco Masci (francescomasci@outlook.com)
 *
 * @brief This file implements the discover hooking mechanism for syscalls. It
 *	provides functions to set up and clean up the discover hooking mode, the
 *	mechanism to save and restore the original syscall table, and helper functions.
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
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/set_memory.h>
#include <linux/moduleloader.h>
#include <linux/numa.h>
#include <asm/pgtable.h>
#include <asm/page.h>
#include <asm/ptrace.h>

#include "disc.h"
#include "sthack.h"
#include "../../sct.h"
#include "../../_syst.h"

#include "./lib/vtpmo.h"

extern int sys_vtpmo(unsigned long vaddr);

#define ADDRESS_MASK 0xfffffffffffff000

#define START 0xffffffff00000000ULL
#define MAX_ADDR 0xfffffffffff00000ULL
#define FIRST_NI_SYSCALL 134
#define SECOND_NI_SYSCALL 174
#define THIRD_NI_SYSCALL 182
#define FOURTH_NI_SYSCALL 183
#define FIFTH_NI_SYSCALL 214
#define SIXTH_NI_SYSCALL 215
#define SEVENTH_NI_SYSCALL 236

#define ENTRIES_TO_EXPLORE 256

static int good_area(unsigned long *);
static int validate_page(unsigned long *);
static void syscall_table_finder(void);
unsigned long **get_syscall_table_addr(void);
unsigned long *get_original_syscall_addrs(void);

// Pointer to the located syscall table
static unsigned long **hacked_syscall_tbl;
// Array to save original syscall addresses
static unsigned long *original_syscall_addrs;

/**
 * @brief Get the syscall table address
 *
 * @return unsigned long** Address of the syscall table
 */
unsigned long **get_syscall_table_addr(void)
{
	return hacked_syscall_tbl;
}

/**
 * @brief Get the array of original syscall addresses
 *
 * @return unsigned long* Array of original syscall addresses
 */
unsigned long *get_original_syscall_addrs(void)
{
	return original_syscall_addrs;
}

/**
 * @brief Checks if the area is good for syscall table
 *
 * @param addr Address to check
 * @return int 1 if good, 0 otherwise
 */
static int good_area(unsigned long *addr)
{
	int i;

	for (i = 1; i < FIRST_NI_SYSCALL; i++) {
		if (addr[i] == addr[FIRST_NI_SYSCALL])
			goto bad_area;
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
static int validate_page(unsigned long *addr)
{
	int i = 0;
	unsigned long page = (unsigned long)addr;
	unsigned long new_page = (unsigned long)addr;

	for (; i < PAGE_SIZE; i += sizeof(void *)) {
		new_page = page + i + SEVENTH_NI_SYSCALL * sizeof(void *);

		// If the table occupies 2 pages check if the second one is materialized in a frame
		if (((page + PAGE_SIZE) == (new_page & ADDRESS_MASK)) && sys_vtpmo(new_page) == NO_MAP)
			break;
		// go for patter matching
		addr = (unsigned long *)(page + i);
		if (((addr[FIRST_NI_SYSCALL] & 0x3) == 0) && (addr[FIRST_NI_SYSCALL] != 0x0) // not points to 0x0
		    && (addr[FIRST_NI_SYSCALL] > 0xffffffff00000000) // not points to a locatio lower than 0xffffffff00000000
		    //&& ( (addr[FIRST_NI_SYSCALL] & START) == START )
		    && (addr[FIRST_NI_SYSCALL] == addr[SECOND_NI_SYSCALL]) && (addr[FIRST_NI_SYSCALL] == addr[THIRD_NI_SYSCALL]) && (addr[FIRST_NI_SYSCALL] == addr[FOURTH_NI_SYSCALL]) &&
		    (addr[FIRST_NI_SYSCALL] == addr[FIFTH_NI_SYSCALL]) && (addr[FIRST_NI_SYSCALL] == addr[SIXTH_NI_SYSCALL]) && (addr[FIRST_NI_SYSCALL] == addr[SEVENTH_NI_SYSCALL]) &&
		    (good_area(addr))) {
			hacked_syscall_tbl = (void *)(addr);
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
static void syscall_table_finder(void)
{
	unsigned long k; // current page
	unsigned long candidate; // current page

	for (k = START; k < MAX_ADDR; k += 4096) {
		candidate = k;
		if (sys_vtpmo(candidate) != NO_MAP) {
			// check if candidate maintains the syscall_table
			if (validate_page((unsigned long *)(candidate)))
				break;
		}
	}
}

#if KERNEL_VERSION(5, 15, 0) <= LINUX_VERSION_CODE

#define STUB_MAGIC 0x504552534953544ULL
#define TABLE_PLACEHOLDER 0x1122334455667788ULL
#define THUNK_PLACEHOLDER 0x9988776655443322ULL

// Use absolute jump to allow jumping to addresses beyond the 2GB limit of relative jumps
#define REL_JMP_LEN 5
#define ABS_JMP_LEN 14

static int used_abs_jmp;

static unsigned long x64_sys_call_addr;
static char original_x64_sys_call_inst[ABS_JMP_LEN];
static int offset;

// Union for atomic jump patching
// Used only for relative jumps
static union _jmp_patch {
	unsigned long val;
	unsigned char bytes[8];
} jmp_patch_rel;

static unsigned char jmp_patch_abs[ABS_JMP_LEN];

/**
 * @brief Calls the original syscall from syscall table
 *
 * This function is the template for the persistent stub that will be called from the JMP in x64_sys_call.
 * It retrieves the syscall number from rax, looks up the corresponding handler in the hacked_syscall_tbl, and jumps to it.
 *
 * RAX contains the syscall number.
 * RDI contains the pointer to pt_regs.
 *
 */
__asm__(".pushsection .rodata\n"
	".align 8\n"
	".global call_stub_start\n"
	"call_stub_start:\n"
	".quad 0x504552534953544\n" // MAGIC
	"movabs $0x1122334455667788, %r11\n" // TABLE_PLACEHOLDER
	"mov (%r11,%rax,8), %rax\n"

	".global call_stub_jmp_target\n"
	"call_stub_jmp_target:\n"
	"movabs $0x9988776655443322, %r11\n" // THUNK_PLACEHOLDER
	"jmp *%r11\n"

	// Get the address of the thunk
	"call_stub_rel_thunk_call:\n"
	"jmp __x86_indirect_thunk_rax\n"

	".global call_stub_end\n"
	"call_stub_end:\n"
	".popsection\n");

// Declare symbols
extern char call_stub_start[];
extern char call_stub_jmp_target[];
extern char call_stub_rel_thunk_call[];
extern char call_stub_end[];

static unsigned long p_stub_addr;

/**
 * @brief Finds the address of a symbol in kernel space
 *
 * @param sym Name of the symbol to find
 * @return unsigned long Address of the symbol if found, 0 otherwise
 */
static int find_symbol_addr(const char *sym, unsigned long *addr)
{
	struct kprobe kp = { .symbol_name = sym };
	int ret = 0;

	if (!addr)
		return -EINVAL;

	*addr = 0;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		PR_ERROR("Cannot register kprobe for symbol '%s'\n", sym);
		return ret;
	}
	*addr = (unsigned long)kp.addr;
	unregister_kprobe(&kp);

	return ret;
}

/**
 * @brief Finds an existing persistent stub in memory to reuse it, or returns 0 if not found
 *
 * @return unsigned long Address of the existing stub if found, 0 otherwise
 */
static unsigned long find_existing_stub(void)
{
	unsigned long addr;

	// If the stub was already set up, return its address to reuse it and avoid multiple allocations
	if (p_stub_addr)
		return p_stub_addr;

	for (addr = MODULES_VADDR; addr < MODULES_END - PAGE_SIZE; addr += PAGE_SIZE) {
		// We check for the presence of the magic number in the first 8 bytes of the page to identify a potential stub.
		// This is a simple heuristic that relies on the uniqueness of the magic number and the assumption that it won't appear by chance in other memory regions.
		//
		// If the magic number is found, we can further verify that it's indeed our stub by checking additional properties if needed.
		unsigned long magic;

		if (copy_from_kernel_nofault(&magic, (void *)addr, sizeof(magic)) == 0) {
			if (magic == STUB_MAGIC) {
				PR_DEBUG("Persistent stub found at 0x%lx\n", addr);
				return addr;
			}
		}
	}

	return 0;
}

typedef void *(*module_alloc_t)(unsigned long);
//typedef void *(*vmalloc_node_range_t)(unsigned long size, unsigned long align,
//				unsigned long start, unsigned long end,
//				gfp_t gfp_mask, pgprot_t prot,
//				unsigned long vm_flags, int node,
//				const void *caller);

/**
 * @brief Set the up persistent stub for syscall dispatching
 *
 * @return int 0 if the stub was set up successfully, 1 if it was found and reused, negative on error
 */
static int setup_persistent_stub(void)
{
	module_alloc_t module_alloc = NULL;
	// vmalloc_node_range_t vmalloc_node_range = NULL;

	unsigned long dummy_jmp_addr = (unsigned long)call_stub_rel_thunk_call;
	int orig_offset = 0;
	unsigned long thunk_addr = 0;

	size_t stub_size = call_stub_end - call_stub_start;
	unsigned char *stub_ptr;
	int i, ret;

	// Search for an existing stub (e.g., from a previous insmod) to reuse it and avoid multiple allocations
	p_stub_addr = find_existing_stub();
	if (p_stub_addr) {
		PR_INFO("Persistent stub found and reused\n");
		return 1;
	}

	// Check if syscall table is found before setting up the stub, as the stub relies on it
	if (!hacked_syscall_tbl) {
		PR_ERROR("Syscall table not found, cannot set up persistent stub\n");
		return -EINVAL;
	}

	// Try to allocate using module_alloc
	if (!p_stub_addr) {
		ret = find_symbol_addr("module_alloc", (unsigned long *)&module_alloc);
		if (!ret && module_alloc) {
			p_stub_addr = (unsigned long) module_alloc(PAGE_SIZE);
			if (p_stub_addr) {
				used_abs_jmp = 0;
				PR_DEBUG("Allocated stub using module_alloc\n");
			}
		}
	}

	// Try to allocate using vmalloc_node_range_noprof
	// Call __vmalloc_node_range_noprof with function pointer on Kernel 6.10+
	// This will trigger Intel CET / IBT protection (Missing ENDBR) causing Kernel Panic.
	//if (!p_stub_addr) {
	//	ret = find_symbol_addr("__vmalloc_node_range_noprof", (unsigned long *)&vmalloc_node_range);
	//
	//	// Try the classic version (kernel <= 6.9)
	//	if (ret < 0 || !vmalloc_node_range)
	//		ret = find_symbol_addr("__vmalloc_node_range", (unsigned long *)&vmalloc_node_range);
	//
	//	if (!ret && vmalloc_node_range) {
	//		p_stub_addr = (unsigned long)vmalloc_node_range(
	//			PAGE_SIZE,		      // Size
	//			PAGE_SIZE,		      // Alignment
	//			MODULES_VADDR,		  // Start range
	//			MODULES_END,		    // End range
	//			GFP_KERNEL,		     // Allocation flags
	//			PAGE_KERNEL,		    // Initial permissions
	//			0,			      // VM_Flags
	//			NUMA_NO_NODE,		   // NUMA node
	//			__builtin_return_address(0)     // Caller
	//		);
	//		if (p_stub_addr) {
	//			used_abs_jmp = 0;
	//			PR_DEBUG("Allocated stub using __vmalloc_node_range\n");
	//		}
	//	}
	//}

	// Fallback allocation using vmalloc
	if (!p_stub_addr) {
		p_stub_addr = (unsigned long) vmalloc(PAGE_SIZE);
		if (p_stub_addr) {
			used_abs_jmp = 1;
			PR_WARN("Allocated stub using vmalloc.\n");
		}
	}

	if (!p_stub_addr)
		return -ENOMEM;

	// Patch Thunk offset in the JMP instruction in the stub
	orig_offset = *(int *)(dummy_jmp_addr + 1);
	thunk_addr = dummy_jmp_addr + 5 + orig_offset;
	PR_DEBUG("Recovered __x86_indirect_thunk_rax address\n");

	// Copy the stub template to the allocated page
	memcpy((void *)p_stub_addr, (void *)call_stub_start, stub_size);

	// Search for the TABLE_PLACEHOLDER in the stub and replace it with the actual address of the hacked_syscall_tbl
	stub_ptr = (unsigned char *)p_stub_addr;
	for (i = 0; i < stub_size - 8; i++) {
		// Syscall table patch
		if (*(unsigned long *)(stub_ptr + i) == TABLE_PLACEHOLDER) {
			*(unsigned long *)(stub_ptr + i) = (unsigned long)hacked_syscall_tbl;
			PR_DEBUG("Stub patched with the address of the hacked syscall table\n");
		}
		// Thunk patch (abs value)
		if (*(unsigned long *)(stub_ptr + i) == THUNK_PLACEHOLDER) {
			*(unsigned long *)(stub_ptr + i) = thunk_addr;
			PR_DEBUG("Stub patched with the address of the thunk\n");
		}
	}

	// Make the page executable
	set_memory_executable(p_stub_addr, 1);

	return 0;
}

#endif

/**
 * @brief Set up discover hooking mode
 *
 * @return int
 */
int setup_discover_hook(void)
{
	unsigned long target_addr;
	int ret = 0;

	// Find syscall table
	syscall_table_finder();
	if (!hacked_syscall_tbl) {
		PR_ERROR("Failed to find the sys_call_table\n");
		return -EINVAL;
	}
	PR_DEBUG("Syscall table found\n");

	// Save original syscall addresses
	original_syscall_addrs = kcalloc(SYSCALL_TABLE_SIZE, sizeof(unsigned long), GFP_KERNEL);
	if (!original_syscall_addrs) {
		PR_ERROR("Cannot allocate memory for saving original syscall addresses\n");
		return -ENOMEM;
	}
	memcpy(original_syscall_addrs, hacked_syscall_tbl, sizeof(unsigned long) * SYSCALL_TABLE_SIZE);
	PR_DEBUG("Original syscall addresses saved\n");

#if KERNEL_VERSION(5, 15, 0) <= LINUX_VERSION_CODE

	// Set up persistent stub for syscall dispatching
	ret = setup_persistent_stub();
	if (ret < 0) {
		PR_ERROR("Failed to set up the persistent stub\n");
		goto persistent_stub_err;
	}

	// Jump the magic number
	target_addr = p_stub_addr + 8;

	ret = find_symbol_addr("x64_sys_call", &x64_sys_call_addr);
	if (ret < 0) {
		PR_ERROR("Cannot find x64_sys_call address\n");
		goto find_x64syscall_err;
	}
	PR_DEBUG("x64_sys_call address found\n");

	// Save original instruction
	memcpy(original_x64_sys_call_inst, (unsigned char *)x64_sys_call_addr, ABS_JMP_LEN);
	PR_DEBUG("Original instruction of x64_sys_call saved\n");

	if (!used_abs_jmp) {
		offset = (int)(target_addr - x64_sys_call_addr - REL_JMP_LEN);
		jmp_patch_rel.val = *(unsigned long *)x64_sys_call_addr;
		jmp_patch_rel.bytes[0] = 0xE9;
		*(int *)(&jmp_patch_rel.bytes[1]) = offset;
	} else {
		// jmp [rip + 0] (Opcodes: FF 25 00 00 00 00)
		jmp_patch_abs[0] = 0xff;
		jmp_patch_abs[1] = 0x25;
		jmp_patch_abs[2] = 0x00;
		jmp_patch_abs[3] = 0x00;
		jmp_patch_abs[4] = 0x00;
		jmp_patch_abs[5] = 0x00;
		// Insert absolute 64-bit address right after
		*(unsigned long *)(&jmp_patch_abs[6]) = target_addr;
	}
	PR_DEBUG("Jump instruction for x64_sys_call prepared\n");

#endif

	begin_syscall_table_hack();
	PR_DEBUG("Syscall table hacking started\n");

#if KERNEL_VERSION(5, 15, 0) <= LINUX_VERSION_CODE
	if (!used_abs_jmp)
		WRITE_ONCE(*(unsigned long *)x64_sys_call_addr, jmp_patch_rel.val);
	else
		memcpy((void *)x64_sys_call_addr, jmp_patch_abs, ABS_JMP_LEN);
	PR_DEBUG("Hack installed on x64_sys_call\n");
#endif
	end_syscall_table_hack();
	PR_DEBUG("Syscall table hacking ended\n");

	return 0;

#if KERNEL_VERSION(5, 15, 0) <= LINUX_VERSION_CODE
persistent_stub_err:
find_x64syscall_err:
	kfree(original_syscall_addrs);
	return ret;
#endif
}

/**
 * @brief Clean up discover hooking mode
 *
 */
void cleanup_discover_hook(void)
{
	size_t i;

	// Prepare the original instruction to restore on x64_sys_call
	if (!used_abs_jmp)
		memcpy(&jmp_patch_rel.bytes, original_x64_sys_call_inst, REL_JMP_LEN);

	begin_syscall_table_hack();
	PR_DEBUG("Syscall table hacking started for cleanup\n");

	// Restore original syscall table
	for (i = 0; i < SYSCALL_TABLE_SIZE; i++)
		WRITE_ONCE(hacked_syscall_tbl[i], (unsigned long *)original_syscall_addrs[i]);
	PR_DEBUG("Original syscall table restored\n");

#if KERNEL_VERSION(5, 15, 0) <= LINUX_VERSION_CODE
	// Restore original x64_sys_call instruction
	if (!used_abs_jmp)
		WRITE_ONCE(*(unsigned long *)x64_sys_call_addr, jmp_patch_rel.val);
	else
		memcpy((void *)x64_sys_call_addr, original_x64_sys_call_inst, ABS_JMP_LEN);
	PR_DEBUG("Original instruction restored on x64_sys_call.\n");
#endif
	end_syscall_table_hack();
	PR_DEBUG("Syscall table hacking ended for cleanup\n");

	// Free allocated memory
	kfree(original_syscall_addrs);
	PR_DEBUG("Memory for original syscall addresses freed\n");
}
